from datetime import timedelta

import pytest

from phoenix_os.configuration import SecretValue
from phoenix_os.inference import (
    InferenceCredentialBroker,
    InferenceCredentialUnavailableError,
    ModelCredentialPolicy,
)
from phoenix_os.policy import PrincipalType, SecurityContext
from phoenix_os.secrets import (
    SecretLeaseRevokedError,
    SecretRef,
    SecretsManager,
)


def _context() -> SecurityContext:
    return SecurityContext(
        principal="system:inference",
        principal_type=PrincipalType.SYSTEM,
        authenticated=True,
        permissions=frozenset(
            {
                "secret.create",
                "secret.read",
                "secret.lease.revoke",
            }
        ),
    )


@pytest.mark.asyncio
async def test_credential_broker_leases_exact_version_and_revokes_on_exit() -> None:
    secrets = SecretsManager()
    context = _context()
    metadata = await secrets.create(
        SecretRef("provider-key", "models"),
        SecretValue("top-secret"),
        context,
    )
    policy = ModelCredentialPolicy(
        secret_ref=metadata.ref,
        lease_ttl=timedelta(seconds=20),
    )
    broker = InferenceCredentialBroker(secrets, context)

    async with broker.lease(policy) as credential:
        lease_id = credential.id
        assert credential.ref == SecretRef("provider-key", "models", 1)
        assert credential.value.reveal(str) == "top-secret"
        assert credential.expires_in == timedelta(seconds=20)
        assert "top-secret" not in repr(credential)

    with pytest.raises(SecretLeaseRevokedError):
        await secrets.resolve_lease(lease_id, context)


@pytest.mark.asyncio
async def test_credential_broker_revokes_when_adapter_body_fails() -> None:
    secrets = SecretsManager()
    context = _context()
    metadata = await secrets.create(
        SecretRef("provider-key", "models"),
        SecretValue("value"),
        context,
    )
    broker = InferenceCredentialBroker(secrets, context)
    lease_id = None

    with pytest.raises(RuntimeError, match="adapter failed"):
        async with broker.lease(ModelCredentialPolicy(metadata.ref)) as credential:
            lease_id = credential.id
            raise RuntimeError("adapter failed")

    assert lease_id is not None
    with pytest.raises(SecretLeaseRevokedError):
        await secrets.resolve_lease(lease_id, context)


def test_credential_policy_requires_exact_version_and_bounded_ttl() -> None:
    with pytest.raises(ValueError, match="exact"):
        ModelCredentialPolicy(SecretRef("provider-key", "models"))
    with pytest.raises(ValueError, match="positive"):
        ModelCredentialPolicy(
            SecretRef("provider-key", "models", 1),
            lease_ttl=timedelta(0),
        )
    with pytest.raises(ValueError, match="maximum"):
        ModelCredentialPolicy(
            SecretRef("provider-key", "models", 1),
            lease_ttl=timedelta(minutes=6),
        )


def test_credential_broker_requires_trusted_runtime_identity() -> None:
    secrets = SecretsManager()

    with pytest.raises(ValueError, match="authenticated"):
        InferenceCredentialBroker(secrets, SecurityContext())
    with pytest.raises(ValueError, match="system or service"):
        InferenceCredentialBroker(
            secrets,
            SecurityContext(
                principal="user:joao",
                principal_type=PrincipalType.USER,
                authenticated=True,
            ),
        )


@pytest.mark.asyncio
async def test_missing_credentials_fail_generically_without_secret_enumeration() -> None:
    broker = InferenceCredentialBroker(SecretsManager(), _context())
    policy = ModelCredentialPolicy(SecretRef("missing-provider-key", "models", 1))

    with pytest.raises(
        InferenceCredentialUnavailableError,
        match="credential is unavailable",
    ) as captured:
        async with broker.lease(policy):
            raise AssertionError("unreachable")

    assert "missing-provider-key" not in str(captured.value)
    assert "#1" not in str(captured.value)
