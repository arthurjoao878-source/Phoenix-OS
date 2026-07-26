import pytest

from phoenix_os.inference import (
    DeterministicModelProvider,
    InferenceRegistryClosedError,
    ModelAlreadyRegisteredError,
    ModelCapabilities,
    ModelCapabilityMismatchError,
    ModelDescriptor,
    ModelId,
    ModelNotFoundError,
    ModelProviderAlreadyRegisteredError,
    ModelProviderId,
    ModelProviderNotFoundError,
    ModelProviderRegistry,
)


def _descriptor(
    provider: str,
    model: str,
    *,
    streaming: bool = True,
) -> ModelDescriptor:
    return ModelDescriptor(
        provider_id=ModelProviderId(provider),
        model_id=ModelId(model),
        provider_model_name=f"{provider}/{model}",
        capabilities=ModelCapabilities(complete=True, streaming=streaming),
    )


def test_registry_registers_and_resolves_in_deterministic_order() -> None:
    registry = ModelProviderRegistry()
    second = DeterministicModelProvider({"b": "B"}, provider_id="second")
    first = DeterministicModelProvider({"a": "A"}, provider_id="first")

    registry.register_provider(second)
    registry.register_provider(first)
    registry.register_model(_descriptor("second", "b"))
    registry.register_model(_descriptor("first", "a"))

    assert registry.list_provider_ids() == (
        ModelProviderId("second"),
        ModelProviderId("first"),
    )
    assert tuple(item.model_id for item in registry.list_models()) == (
        ModelId("b"),
        ModelId("a"),
    )
    assert registry.resolve_provider("first") is first
    assert registry.resolve_model("second", "b").provider_model_name == "second/b"


def test_registry_rejects_duplicate_provider_and_model() -> None:
    registry = ModelProviderRegistry()
    provider = DeterministicModelProvider({"chat": "hello"}, provider_id="fake")
    descriptor = _descriptor("fake", "chat")

    registry.register_provider(provider)
    registry.register_model(descriptor)

    with pytest.raises(ModelProviderAlreadyRegisteredError):
        registry.register_provider(provider)
    with pytest.raises(ModelAlreadyRegisteredError):
        registry.register_model(descriptor)


def test_registry_rejects_models_without_provider() -> None:
    registry = ModelProviderRegistry()

    with pytest.raises(ModelProviderNotFoundError):
        registry.register_model(_descriptor("missing", "chat"))


class CompleteOnlyProvider(DeterministicModelProvider):
    @property
    def capabilities(self) -> ModelCapabilities:
        return ModelCapabilities(complete=True, streaming=False)


def test_registry_rejects_model_capabilities_above_provider() -> None:
    registry = ModelProviderRegistry()
    registry.register_provider(CompleteOnlyProvider({"chat": "hello"}, provider_id="complete-only"))

    with pytest.raises(ModelCapabilityMismatchError):
        registry.register_model(_descriptor("complete-only", "chat", streaming=True))


def test_registry_raises_safe_not_found_errors() -> None:
    registry = ModelProviderRegistry()
    registry.register_provider(DeterministicModelProvider({"chat": "hello"}, provider_id="fake"))

    with pytest.raises(ModelProviderNotFoundError):
        registry.resolve_provider("missing")
    with pytest.raises(ModelNotFoundError):
        registry.resolve_model("fake", "missing")


def test_registry_filters_models_by_provider() -> None:
    registry = ModelProviderRegistry()
    registry.register_provider(DeterministicModelProvider({"a": "A"}, provider_id="one"))
    registry.register_provider(DeterministicModelProvider({"b": "B"}, provider_id="two"))
    registry.register_model(_descriptor("one", "a"))
    registry.register_model(_descriptor("two", "b"))

    assert registry.list_models("two") == (_descriptor("two", "b"),)


def test_registry_close_is_terminal() -> None:
    registry = ModelProviderRegistry()
    registry.close()

    assert registry.closed is True
    with pytest.raises(InferenceRegistryClosedError):
        registry.list_models()
    with pytest.raises(InferenceRegistryClosedError):
        registry.register_provider(
            DeterministicModelProvider({"chat": "hello"}, provider_id="fake")
        )
