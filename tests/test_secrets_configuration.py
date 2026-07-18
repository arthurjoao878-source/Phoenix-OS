from datetime import timedelta

import pytest

from phoenix_os import (
    ConfigField,
    ConfigLoader,
    ConfigSchema,
    ConfigTypeError,
    MappingConfigSource,
    PrincipalType,
    SecretConfigResolver,
    SecretRef,
    SecretsManager,
    SecretValue,
    SecurityContext,
    parse_secret_ref,
)


def test_parse_secret_ref_supports_latest_and_exact_versions() -> None:
    assert parse_secret_ref("prod/api") == SecretRef("api", "prod")
    assert parse_secret_ref("prod/api#3") == SecretRef("api", "prod", 3)


@pytest.mark.parametrize("value", [None, 7, "", "api", "prod/api#bad", "prod/api#0"])
def test_parse_secret_ref_rejects_invalid_values(value: object) -> None:
    with pytest.raises(ConfigTypeError):
        parse_secret_ref(value)


@pytest.mark.asyncio
async def test_configuration_resolver_issues_lease() -> None:
    configuration = await ConfigLoader(
        ConfigSchema((ConfigField("database.password", parse_secret_ref),)),
        (MappingConfigSource({"database.password": "prod/db-password"}),),
    ).load()
    context = SecurityContext(
        principal="service:api",
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
        permissions=frozenset({"secret.create", "secret.read"}),
    )
    manager = SecretsManager()
    await manager.create(
        SecretRef("db-password", "prod"),
        SecretValue("secret"),
        context,
    )
    lease = await SecretConfigResolver(manager, context).lease(
        configuration,
        "database.password",
        ttl=timedelta(minutes=1),
    )
    assert lease.value.reveal(str) == "secret"
