import pytest

from phoenix_os.kernel import Request, Response, RouteNotFoundError, Router


async def handler(request: Request) -> Response:
    del request
    return Response(status=200)


def test_router_adds_and_resolves_route() -> None:
    router = Router()
    route = router.add("ping", handler, sensitive=True)

    assert router.resolve("ping") is route
    assert route.sensitive is True


def test_router_rejects_duplicate_route() -> None:
    router = Router()
    router.add("ping", handler)

    with pytest.raises(ValueError, match="already registered"):
        router.add("ping", handler)


def test_router_rejects_blank_route() -> None:
    router = Router()

    with pytest.raises(ValueError, match="blank"):
        router.add("  ", handler)


def test_router_raises_typed_error_for_missing_route() -> None:
    router = Router()

    with pytest.raises(RouteNotFoundError):
        router.resolve("missing")
