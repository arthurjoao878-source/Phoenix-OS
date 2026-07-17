"""Route registry separated from Kernel orchestration."""

from phoenix_os.kernel.contracts import Handler, Route
from phoenix_os.kernel.errors import RouteNotFoundError


class Router:
    def __init__(self) -> None:
        self._routes: dict[str, Route] = {}

    def add(self, action: str, handler: Handler, *, sensitive: bool = False) -> Route:
        normalized = action.strip()
        if not normalized:
            raise ValueError("action must not be blank")
        if normalized in self._routes:
            raise ValueError(f"route already registered: {normalized}")
        route = Route(action=normalized, handler=handler, sensitive=sensitive)
        self._routes[normalized] = route
        return route

    def resolve(self, action: str) -> Route:
        try:
            return self._routes[action]
        except KeyError as exception:
            raise RouteNotFoundError(f"no route for action {action!r}") from exception
