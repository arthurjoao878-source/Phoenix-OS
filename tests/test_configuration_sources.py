from pathlib import Path

import pytest

from phoenix_os.configuration import (
    ConfigSourceError,
    EnvironmentConfigSource,
    JsonFileConfigSource,
    MappingConfigSource,
)


@pytest.mark.asyncio
async def test_mapping_source_normalizes_and_freezes_values() -> None:
    values: dict[str, object] = {" Runtime.Port ": 8080}
    data = await MappingConfigSource(values, name="defaults").load()
    values[" Runtime.Port "] = 9000

    assert data.source == "defaults"
    assert data.values == {"runtime.port": 8080}
    assert data.raw_key("runtime.port") == " Runtime.Port "
    with pytest.raises(TypeError):
        data.values["other"] = 1  # type: ignore[index]


@pytest.mark.asyncio
async def test_mapping_source_rejects_duplicate_normalized_keys() -> None:
    with pytest.raises(ConfigSourceError, match="duplicate"):
        await MappingConfigSource({"runtime.port": 1, " RUNTIME.PORT ": 2}).load()


@pytest.mark.asyncio
async def test_environment_source_filters_prefix_and_maps_separator() -> None:
    source = EnvironmentConfigSource(
        prefix="PHOENIX_",
        environ={
            "PHOENIX_RUNTIME__PORT": "8080",
            "PHOENIX_AUTH__TOKEN": "secret",
            "OTHER_VALUE": "ignored",
        },
    )

    data = await source.load()

    assert data.values == {"runtime.port": "8080", "auth.token": "secret"}


@pytest.mark.asyncio
async def test_environment_source_validates_options() -> None:
    with pytest.raises(ValueError, match="prefix"):
        EnvironmentConfigSource(prefix="")
    with pytest.raises(ValueError, match="separator"):
        EnvironmentConfigSource(separator="")


@pytest.mark.asyncio
async def test_json_source_flattens_nested_objects(tmp_path: Path) -> None:
    path = tmp_path / "phoenix.json"
    path.write_text(
        '{"runtime": {"port": 8080, "debug": true}, "features": ["voice", "tools"]}',
        encoding="utf-8",
    )

    data = await JsonFileConfigSource(path).load()

    assert data.values == {
        "runtime.port": 8080,
        "runtime.debug": True,
        "features": ["voice", "tools"],
    }


@pytest.mark.asyncio
async def test_json_source_supports_optional_missing_file(tmp_path: Path) -> None:
    path = tmp_path / "missing.json"
    data = await JsonFileConfigSource(path, optional=True).load()
    assert data.values == {}


@pytest.mark.asyncio
async def test_json_source_rejects_missing_invalid_and_non_object_files(tmp_path: Path) -> None:
    missing = tmp_path / "missing.json"
    with pytest.raises(ConfigSourceError, match="not found"):
        await JsonFileConfigSource(missing).load()

    invalid = tmp_path / "invalid.json"
    invalid.write_text("{", encoding="utf-8")
    with pytest.raises(ConfigSourceError, match="invalid JSON"):
        await JsonFileConfigSource(invalid).load()

    array = tmp_path / "array.json"
    array.write_text("[]", encoding="utf-8")
    with pytest.raises(ConfigSourceError, match="root"):
        await JsonFileConfigSource(array).load()
