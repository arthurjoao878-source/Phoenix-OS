from datetime import datetime

import pytest

from phoenix_os.capabilities import (
    CapabilityContext,
    CapabilityDescriptor,
    CapabilityInvocation,
    CapabilityResult,
    RiskLevel,
)


def test_descriptor_normalizes_name_and_freezes_collections() -> None:
    descriptor = CapabilityDescriptor(
        name="  system.echo  ",
        risk=RiskLevel.SENSITIVE,
        required_permissions=frozenset({" system.read "}),
        tags=frozenset({" demo "}),
    )

    assert descriptor.name == "system.echo"
    assert descriptor.required_permissions == frozenset({"system.read"})
    assert descriptor.tags == frozenset({"demo"})


def test_descriptor_rejects_blank_name_and_version() -> None:
    with pytest.raises(ValueError, match="name"):
        CapabilityDescriptor(name="  ")
    with pytest.raises(ValueError, match="version"):
        CapabilityDescriptor(name="system.echo", version=" ")


def test_descriptor_rejects_non_positive_timeout() -> None:
    with pytest.raises(ValueError, match="default_timeout"):
        CapabilityDescriptor(name="system.echo", default_timeout=0)


def test_descriptor_rejects_blank_permission_or_tag() -> None:
    with pytest.raises(ValueError, match="blank"):
        CapabilityDescriptor(name="system.echo", required_permissions=frozenset({" "}))
    with pytest.raises(ValueError, match="blank"):
        CapabilityDescriptor(name="system.echo", tags=frozenset({" "}))


def test_context_freezes_permissions_and_metadata() -> None:
    metadata = {"channel": "voice"}
    context = CapabilityContext(
        principal="joao",
        permissions=frozenset({" system.read "}),
        metadata=metadata,
    )
    metadata["channel"] = "changed"

    assert context.permissions == frozenset({"system.read"})
    assert context.metadata == {"channel": "voice"}
    with pytest.raises(TypeError):
        context.metadata["other"] = "value"  # type: ignore[index]


def test_context_rejects_blank_principal() -> None:
    with pytest.raises(ValueError, match="principal"):
        CapabilityContext(principal=" ")


def test_invocation_freezes_arguments() -> None:
    arguments: dict[str, object] = {"message": "hello"}
    invocation = CapabilityInvocation(capability=" system.echo ", arguments=arguments)
    arguments["message"] = "changed"

    assert invocation.capability == "system.echo"
    assert invocation.arguments == {"message": "hello"}
    with pytest.raises(TypeError):
        invocation.arguments["new"] = True  # type: ignore[index]


def test_invocation_requires_timezone_aware_timestamp() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        CapabilityInvocation(capability="system.echo", created_at=datetime.now())


def test_result_freezes_output_and_metadata() -> None:
    invocation = CapabilityInvocation(capability="system.echo")
    output: dict[str, object] = {"reply": "pong"}
    metadata = {"provider": "demo"}
    result = CapabilityResult(
        invocation_id=invocation.id,
        output=output,
        metadata=metadata,
    )
    output["reply"] = "changed"
    metadata["provider"] = "changed"

    assert result.output == {"reply": "pong"}
    assert result.metadata == {"provider": "demo"}
