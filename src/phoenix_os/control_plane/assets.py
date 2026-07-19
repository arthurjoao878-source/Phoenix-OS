"""Immutable packaged assets for the dependency-free Phoenix dashboard."""

from __future__ import annotations

from dataclasses import dataclass
from importlib.resources import files
from types import MappingProxyType


@dataclass(frozen=True, slots=True)
class DashboardAsset:
    """One allowlisted static dashboard asset."""

    path: str
    content_type: str
    body: bytes

    def __post_init__(self) -> None:
        path = self.path.strip()
        content_type = self.content_type.strip()
        if not path.startswith("/dashboard/"):
            raise ValueError("dashboard asset path must be rooted under /dashboard/")
        if not content_type:
            raise ValueError("dashboard asset content type must not be blank")
        if not self.body:
            raise ValueError("dashboard asset body must not be empty")
        object.__setattr__(self, "path", path)
        object.__setattr__(self, "content_type", content_type)


class DashboardAssets:
    """Load a fixed package manifest without accepting filesystem paths from clients."""

    _MANIFEST = MappingProxyType(
        {
            "/dashboard/": ("dashboard/index.html", "text/html; charset=utf-8"),
            "/dashboard/app.css": ("dashboard/app.css", "text/css; charset=utf-8"),
            "/dashboard/app.js": ("dashboard/app.js", "text/javascript; charset=utf-8"),
            "/dashboard/favicon.svg": ("dashboard/favicon.svg", "image/svg+xml"),
        }
    )

    def __init__(self) -> None:
        package = files("phoenix_os.control_plane")
        loaded: dict[str, DashboardAsset] = {}
        for path, (resource_name, content_type) in self._MANIFEST.items():
            body = package.joinpath(resource_name).read_bytes()
            loaded[path] = DashboardAsset(path, content_type, body)
        self._assets = MappingProxyType(loaded)

    def get(self, path: str) -> DashboardAsset | None:
        """Return only an exact allowlisted asset path."""

        return self._assets.get(path)

    def paths(self) -> tuple[str, ...]:
        return tuple(self._assets)
