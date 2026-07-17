import pytest

from phoenix_os.configuration import (
    ConfigDecodeError,
    ConfigField,
    ConfigLoader,
    ConfigMissingError,
    ConfigSchema,
    ConfigUnknownKeyError,
    ConfigValidationError,
    EnvironmentConfigSource,
    MappingConfigSource,
    UnknownKeyPolicy,
    as_boolean,
    as_integer,
    as_string,
    positive,
)


def schema(*, unknown: UnknownKeyPolicy = UnknownKeyPolicy.REJECT) -> ConfigSchema:
    return ConfigSchema(
        (
            ConfigField("runtime.port", as_integer, validator=positive),
            ConfigField("runtime.debug", as_boolean, default=False),
            ConfigField("runtime.mode", as_string, default="development"),
            ConfigField("auth.token", as_string, secret=True),
        ),
        unknown_keys=unknown,
    )


@pytest.mark.asyncio
async def test_loader_applies_later_source_precedence_and_tracks_origin() -> None:
    loader = ConfigLoader(
        schema(),
        (
            MappingConfigSource(
                {
                    "runtime.port": 8000,
                    "runtime.mode": "development",
                    "auth.token": "default-token",
                },
                name="file",
            ),
            EnvironmentConfigSource(
                environ={
                    "PHOENIX_RUNTIME__PORT": "9000",
                    "PHOENIX_AUTH__TOKEN": "environment-token",
                }
            ),
        ),
    )

    configuration = await loader.load()

    assert configuration.value("runtime.port", int) == 9000
    assert configuration.value("runtime.debug", bool) is False
    assert configuration.value("runtime.mode", str) == "development"
    assert configuration.secret("auth.token").reveal(str) == "environment-token"
    assert configuration.origin("runtime.port").source == "environment"
    assert configuration.origin("runtime.debug").source == "default"


@pytest.mark.asyncio
async def test_loader_is_repeatable_and_does_not_mutate_sources() -> None:
    source_values: dict[str, object] = {"runtime.port": 8080, "auth.token": "token"}
    loader = ConfigLoader(schema(), (MappingConfigSource(source_values),))

    first = await loader.load()
    second = await loader.load()

    assert first.as_dict(reveal_secrets=True) == second.as_dict(reveal_secrets=True)
    assert source_values == {"runtime.port": 8080, "auth.token": "token"}


@pytest.mark.asyncio
async def test_loader_rejects_missing_required_field() -> None:
    loader = ConfigLoader(
        schema(),
        (MappingConfigSource({"runtime.port": 8080}),),
    )
    with pytest.raises(ConfigMissingError) as captured:
        await loader.load()
    assert captured.value.key == "auth.token"


@pytest.mark.asyncio
async def test_loader_rejects_unknown_keys_in_strict_mode() -> None:
    loader = ConfigLoader(
        schema(),
        (MappingConfigSource({"runtime.port": 8080, "auth.token": "token", "unknown.value": 1}),),
    )
    with pytest.raises(ConfigUnknownKeyError) as captured:
        await loader.load()
    assert captured.value.keys == ("unknown.value",)


@pytest.mark.asyncio
async def test_loader_can_ignore_unknown_keys_explicitly() -> None:
    loader = ConfigLoader(
        schema(unknown=UnknownKeyPolicy.IGNORE),
        (MappingConfigSource({"runtime.port": 8080, "auth.token": "token", "unknown.value": 1}),),
    )
    configuration = await loader.load()
    assert "unknown.value" not in configuration.values


@pytest.mark.asyncio
async def test_loader_wraps_decode_failures_without_exposing_secret_values() -> None:
    loader = ConfigLoader(
        schema(),
        (MappingConfigSource({"runtime.port": "not-a-number", "auth.token": "secret"}),),
    )
    with pytest.raises(ConfigDecodeError) as captured:
        await loader.load()
    assert captured.value.key == "runtime.port"
    assert "not-a-number" not in str(captured.value)


@pytest.mark.asyncio
async def test_loader_runs_validators_for_source_and_default_values() -> None:
    invalid_source = ConfigLoader(
        schema(),
        (MappingConfigSource({"runtime.port": 0, "auth.token": "token"}),),
    )
    with pytest.raises(ConfigValidationError) as captured:
        await invalid_source.load()
    assert captured.value.key == "runtime.port"

    invalid_default_schema = ConfigSchema(
        (ConfigField("runtime.port", as_integer, default=0, validator=positive),)
    )
    with pytest.raises(ConfigValidationError):
        await ConfigLoader(invalid_default_schema).load()
