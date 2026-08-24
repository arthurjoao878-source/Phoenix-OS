"""Internal fail-closed errors for RFC-0034 network egress slice 2."""

from __future__ import annotations

import re

_CATEGORY_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


def _validate_category(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError("network error category must be a string")
    if _CATEGORY_PATTERN.fullmatch(value) is None:
        raise ValueError("network error category is invalid")
    return value


class NetworkDestinationRejectedError(ValueError):
    """Fail-closed destination/profile/request rejection without sensitive detail."""

    def __init__(self, category: str) -> None:
        self.category = _validate_category(category)
        super().__init__(f"network destination rejected: {self.category}")


class NetworkTransportError(RuntimeError):
    """Sanitized transport failure carrying whether request bytes may have started."""

    def __init__(self, category: str, *, request_started: bool) -> None:
        self.category = _validate_category(category)
        if not isinstance(request_started, bool):
            raise TypeError("request_started must be a boolean")
        self.request_started = request_started
        super().__init__(f"network transport failed: {self.category}")
