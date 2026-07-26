import asyncio

import pytest

from phoenix_os.inference import (
    InferenceAdmissionController,
    InferenceAdmissionLimits,
    InferenceSaturatedError,
    ModelId,
    ModelProviderId,
)


def test_admission_limits_require_ordered_positive_capacities() -> None:
    with pytest.raises(ValueError, match="greater than zero"):
        InferenceAdmissionLimits(global_concurrency=0)
    with pytest.raises(ValueError, match="provider_concurrency"):
        InferenceAdmissionLimits(
            global_concurrency=1,
            provider_concurrency=2,
        )
    with pytest.raises(ValueError, match="model_concurrency"):
        InferenceAdmissionLimits(
            global_concurrency=2,
            provider_concurrency=1,
            model_concurrency=2,
        )


@pytest.mark.asyncio
async def test_global_capacity_fails_fast() -> None:
    controller = InferenceAdmissionController(
        InferenceAdmissionLimits(
            global_concurrency=1,
            provider_concurrency=1,
            model_concurrency=1,
        )
    )

    async with controller.admit(ModelProviderId("one"), ModelId("chat")):
        with pytest.raises(InferenceSaturatedError):
            async with controller.admit(ModelProviderId("two"), ModelId("chat")):
                raise AssertionError("unreachable")


@pytest.mark.asyncio
async def test_provider_capacity_isolated_from_other_providers() -> None:
    controller = InferenceAdmissionController(
        InferenceAdmissionLimits(
            global_concurrency=3,
            provider_concurrency=1,
            model_concurrency=1,
        )
    )

    async with controller.admit(ModelProviderId("one"), ModelId("chat")):
        with pytest.raises(InferenceSaturatedError):
            async with controller.admit(ModelProviderId("one"), ModelId("other")):
                raise AssertionError("unreachable")
        async with controller.admit(ModelProviderId("two"), ModelId("chat")):
            pass


@pytest.mark.asyncio
async def test_model_capacity_isolated_from_other_models() -> None:
    controller = InferenceAdmissionController(
        InferenceAdmissionLimits(
            global_concurrency=3,
            provider_concurrency=2,
            model_concurrency=1,
        )
    )
    provider = ModelProviderId("one")

    async with controller.admit(provider, ModelId("chat")):
        with pytest.raises(InferenceSaturatedError):
            async with controller.admit(provider, ModelId("chat")):
                raise AssertionError("unreachable")
        async with controller.admit(provider, ModelId("other")):
            pass


@pytest.mark.asyncio
async def test_admission_releases_capacity_after_body_failure() -> None:
    controller = InferenceAdmissionController(
        InferenceAdmissionLimits(
            global_concurrency=1,
            provider_concurrency=1,
            model_concurrency=1,
        )
    )
    provider = ModelProviderId("one")
    model = ModelId("chat")

    with pytest.raises(RuntimeError, match="boom"):
        async with controller.admit(provider, model):
            raise RuntimeError("boom")

    async with controller.admit(provider, model):
        pass


@pytest.mark.asyncio
async def test_concurrent_admission_race_never_exceeds_capacity() -> None:
    controller = InferenceAdmissionController(
        InferenceAdmissionLimits(
            global_concurrency=3,
            provider_concurrency=3,
            model_concurrency=3,
        )
    )
    provider = ModelProviderId("one")
    model = ModelId("chat")
    three_admitted = asyncio.Event()
    release = asyncio.Event()
    admitted: list[int] = []

    async def contender(index: int) -> bool:
        try:
            async with controller.admit(provider, model):
                admitted.append(index)
                if len(admitted) == 3:
                    three_admitted.set()
                await release.wait()
                return True
        except InferenceSaturatedError:
            return False

    tasks = [asyncio.create_task(contender(index)) for index in range(20)]
    await asyncio.wait_for(three_admitted.wait(), timeout=1)
    await asyncio.sleep(0)
    release.set()
    results = await asyncio.gather(*tasks)

    assert sum(results) == 3
    assert len(admitted) == 3


def test_saturation_message_does_not_enumerate_resources() -> None:
    error = InferenceSaturatedError()

    assert str(error) == "inference capacity is unavailable"
    assert "provider" not in str(error)
    assert "model" not in str(error)
