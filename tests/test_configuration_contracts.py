from pathlib import Path

import pytest

from phoenix_os.configuration import (
    ConfigField,
    ConfigKeyError,
    ConfigOrigin,
    ConfigSchema,
    ConfigSecretError,
    ConfigTypeError,
    Configuration,
    SecretValue,
    UnknownKeyPolicy,
    as_integer,
    as_path,
    as_string,
    normalize_key,
)


def test_normalize_key_accepts_dotted_lowercase_names() -> None:
    assert normalize_key(" Runtime.Startup_Deadline ") == "runtime.startup_deadline"


@pytest.mark.parametrize("key", ["", " ", ".name", "name.", "two..parts", "1name", "bad-name"])
def test_normalize_key_rejects_invalid_names(key: str) -> None:
    with pytest.raises(ConfigKeyError):
        normalize_key(key)


def test_config_field_tracks_required_default_and_secret_metadata() -> None:
    required = ConfigField("runtime.port", as_integer)
    optional = ConfigField("runtime.mode", as_string, default="test", secret=True)

    assert required.required is True
    assert optional.required is False
    assert optional.default == "test"
    assert optional.secret is True


def test_schema_rejects_duplicate_normalized_fields() -> None:
    with pytest.raises(ValueError, match="duplicate"):
        ConfigSchema(
            (
                ConfigField("runtime.port", as_integer),
                ConfigField(" RUNTIME.PORT ", as_integer),
            )
        )


def test_schema_defaults_to_strict_unknown_key_handling() -> None:
    schema = ConfigSchema((ConfigField("runtime.port", as_integer),))
    assert schema.unknown_keys is UnknownKeyPolicy.REJECT
    assert tuple(schema.by_key) == ("runtime.port",)


def test_secret_value_is_redacted_and_requires_explicit_reveal() -> None:
    secret = SecretValue("token-value")

    assert repr(secret) == "SecretValue(***)"
    assert str(secret) == "***"
    assert secret.reveal(str) == "token-value"
    with pytest.raises(ConfigTypeError):
        secret.reveal(int)


def test_configuration_is_immutable_and_redacts_secrets() -> None:
    values = {"runtime.port": 8080, "auth.token": SecretValue("secret")}
    origins = {
        "runtime.port": ConfigOrigin("mapping", "runtime.port"),
        "auth.token": ConfigOrigin("environment", "PHOENIX_AUTH__TOKEN"),
    }
    configuration = Configuration(
        values=values,
        origins=origins,
        _sensitive=frozenset({"auth.token"}),
    )
    values["runtime.port"] = 9000

    assert configuration.value("runtime.port", int) == 8080
    assert configuration.secret("auth.token").reveal(str) == "secret"
    assert configuration.as_dict() == {"runtime.port": 8080, "auth.token": "***"}
    assert configuration.as_dict(reveal_secrets=True) == {
        "runtime.port": 8080,
        "auth.token": "secret",
    }
    assert configuration.origin("auth.token").source == "environment"
    with pytest.raises(TypeError):
        configuration.values["other"] = 1  # type: ignore[index]


def test_configuration_rejects_secret_and_type_api_misuse() -> None:
    configuration = Configuration(
        values={"runtime.port": 8080, "auth.token": SecretValue("secret")},
        origins={
            "runtime.port": ConfigOrigin("mapping", "runtime.port"),
            "auth.token": ConfigOrigin("mapping", "auth.token"),
        },
        _sensitive=frozenset({"auth.token"}),
    )

    with pytest.raises(ConfigSecretError):
        configuration.value("auth.token")
    with pytest.raises(ConfigSecretError):
        configuration.secret("runtime.port")
    with pytest.raises(ConfigTypeError):
        configuration.value("runtime.port", str)


def test_path_decoder_does_not_touch_filesystem(tmp_path: Path) -> None:
    path = tmp_path / "missing"
    assert as_path(str(path)) == path
    assert path.exists() is False
