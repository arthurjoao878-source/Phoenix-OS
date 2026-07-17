from datetime import datetime

import pytest

from phoenix_os.runtime import ComponentSpec, HookComponent, RuntimeContext, RuntimeState


def test_runtime_context_freezes_services_and_metadata() -> None:
    services: dict[str, object] = {" cache ": object()}
    metadata = {"environment": "test"}

    context = RuntimeContext(services=services, metadata=metadata)
    services["later"] = object()
    metadata["environment"] = "production"

    assert tuple(context.services) == ("cache",)
    assert context.metadata == {"environment": "test"}
    with pytest.raises(TypeError):
        context.services["other"] = object()  # type: ignore[index]


def test_runtime_context_requires_aware_timestamp() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        RuntimeContext(services={}, created_at=datetime.now())


def test_runtime_context_rejects_blank_or_duplicate_normalized_service_names() -> None:
    with pytest.raises(ValueError, match="blank"):
        RuntimeContext(services={" ": object()})

    with pytest.raises(ValueError, match="duplicate"):
        RuntimeContext(services={"cache": object(), " cache ": object()})


def test_component_spec_normalizes_and_validates_name() -> None:
    component = HookComponent()

    assert ComponentSpec(" cache ", component).name == "cache"
    with pytest.raises(ValueError, match="blank"):
        ComponentSpec(" ", component)


def test_runtime_states_are_stable_strings() -> None:
    assert RuntimeState.CREATED.value == "created"
    assert RuntimeState.RUNNING.value == "running"
    assert RuntimeState.STOPPED.value == "stopped"
