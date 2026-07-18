"""Deterministic canonical serialization for Phoenix audit records."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from datetime import datetime

from phoenix_os.audit.contracts import AuditEvent


def _portable(value: object) -> object:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Mapping):
        return {str(key): _portable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_portable(item) for item in value]
    raise TypeError(f"unsupported canonical audit value: {type(value).__name__}")


def canonical_audit_bytes(
    event: AuditEvent,
    *,
    sequence: int,
    recorded_at: datetime,
    previous_digest: str,
) -> bytes:
    """Return canonical UTF-8 JSON bytes used by the audit digest chain."""

    payload = {
        "sequence": sequence,
        "recorded_at": recorded_at.isoformat(),
        "previous_digest": previous_digest,
        "event": {
            "id": str(event.id),
            "name": event.name,
            "source": event.source,
            "category": event.category.value,
            "action": event.action,
            "resource": event.resource,
            "actor": event.actor,
            "outcome": event.outcome.value,
            "severity": event.severity.value,
            "details": _portable(event.details),
            "occurred_at": event.occurred_at.isoformat(),
            "correlation_id": event.correlation_id,
            "causation_id": None if event.causation_id is None else str(event.causation_id),
        },
    }
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def compute_audit_digest(
    event: AuditEvent,
    *,
    sequence: int,
    recorded_at: datetime,
    previous_digest: str,
) -> str:
    """Compute the lowercase SHA-256 digest for one prospective audit record."""

    canonical = canonical_audit_bytes(
        event,
        sequence=sequence,
        recorded_at=recorded_at,
        previous_digest=previous_digest,
    )
    return hashlib.sha256(canonical).hexdigest()
