"""Canonical audit archive segments, verification, rotation, and retention."""

from __future__ import annotations

import asyncio
import base64
import gzip
import hashlib
import inspect
import json
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Final
from uuid import UUID

from phoenix_os.audit.codec import compute_audit_digest
from phoenix_os.audit.contracts import (
    AUDIT_GENESIS_DIGEST,
    AuditCategory,
    AuditEvent,
    AuditOutcome,
    AuditQuery,
    AuditRecord,
    AuditSeal,
    AuditSeverity,
    AuditSigner,
    AuditStore,
)
from phoenix_os.audit.errors import (
    AuditArchiveError,
    AuditArchiveExistsError,
    AuditArchiveVerificationError,
    AuditRetentionConfirmationError,
    AuditSignerError,
)
from phoenix_os.secrets import KeyRef

if TYPE_CHECKING:
    from collections.abc import Iterable

_ARCHIVE_SCHEMA_VERSION: Final = 1
_MANIFEST_SUFFIX: Final = ".manifest.json"
_PAYLOAD_SUFFIX: Final = ".records.ndjson"
_GZIP_SUFFIX: Final = ".gz"
_DIGEST_LENGTH: Final = 64


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _normalize_digest(value: str, label: str) -> str:
    normalized = value.strip().lower()
    if len(normalized) != _DIGEST_LENGTH or any(
        character not in "0123456789abcdef" for character in normalized
    ):
        raise ValueError(f"{label} must be a lowercase SHA-256 hexadecimal digest")
    return normalized


def _normalize_archive_id(value: str) -> str:
    normalized = value.strip().lower()
    if not normalized or any(
        not (character.isascii() and (character.isalnum() or character in "-_."))
        for character in normalized
    ):
        raise ValueError(
            "archive_id must contain only ASCII letters, numbers, dash, underscore, or dot"
        )
    return normalized


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _portable(value: object) -> object:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Mapping):
        return {str(key): _portable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_portable(item) for item in value]
    raise TypeError(f"unsupported archive value: {type(value).__name__}")


class AuditArchiveCompression(StrEnum):
    """Supported deterministic archive payload encodings."""

    NONE = "none"
    GZIP = "gzip"


@dataclass(frozen=True, slots=True)
class AuditArchiveManifest:
    """Immutable cryptographic description of one contiguous archive segment."""

    archive_id: str
    created_at: datetime
    first_sequence: int
    last_sequence: int
    record_count: int
    anchor_digest: str
    head_digest: str
    payload_digest: str
    artifact_digest: str
    previous_manifest_digest: str
    compression: AuditArchiveCompression
    artifact_name: str
    manifest_digest: str
    schema_version: int = _ARCHIVE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(self, "archive_id", _normalize_archive_id(self.archive_id))
        if self.created_at.tzinfo is None:
            raise ValueError("created_at must be timezone-aware")
        if self.schema_version != _ARCHIVE_SCHEMA_VERSION:
            raise ValueError(f"unsupported archive manifest schema version: {self.schema_version}")
        if self.first_sequence <= 0 or self.last_sequence < self.first_sequence:
            raise ValueError("archive sequence bounds are invalid")
        expected_count = self.last_sequence - self.first_sequence + 1
        if self.record_count != expected_count:
            raise ValueError("record_count must match archive sequence bounds")
        object.__setattr__(
            self, "anchor_digest", _normalize_digest(self.anchor_digest, "anchor_digest")
        )
        object.__setattr__(self, "head_digest", _normalize_digest(self.head_digest, "head_digest"))
        object.__setattr__(
            self, "payload_digest", _normalize_digest(self.payload_digest, "payload_digest")
        )
        object.__setattr__(
            self, "artifact_digest", _normalize_digest(self.artifact_digest, "artifact_digest")
        )
        object.__setattr__(
            self,
            "previous_manifest_digest",
            _normalize_digest(self.previous_manifest_digest, "previous_manifest_digest"),
        )
        object.__setattr__(
            self, "manifest_digest", _normalize_digest(self.manifest_digest, "manifest_digest")
        )
        object.__setattr__(self, "compression", AuditArchiveCompression(self.compression))
        artifact_name = self.artifact_name.strip()
        if not artifact_name or Path(artifact_name).name != artifact_name:
            raise ValueError("artifact_name must be a plain file name")
        object.__setattr__(self, "artifact_name", artifact_name)


@dataclass(frozen=True, slots=True)
class AuditArchiveResult:
    """Files and manifest published for one exported segment."""

    manifest: AuditArchiveManifest
    manifest_path: Path
    artifact_path: Path


@dataclass(frozen=True, slots=True)
class AuditArchiveVerification:
    """Verification result for one archive or an ordered archive chain."""

    valid: bool
    checked_archives: int
    checked_records: int
    head_digest: str
    manifest_digest: str
    signatures_checked: int = 0
    failure_archive_id: str | None = None
    failure_sequence: int | None = None
    reason: str | None = None

    def __post_init__(self) -> None:
        if self.checked_archives < 0 or self.checked_records < 0:
            raise ValueError("archive verification counts cannot be negative")
        if self.signatures_checked < 0 or self.signatures_checked > self.checked_records:
            raise ValueError("signatures_checked must be within checked record count")
        object.__setattr__(self, "head_digest", _normalize_digest(self.head_digest, "head_digest"))
        object.__setattr__(
            self,
            "manifest_digest",
            _normalize_digest(self.manifest_digest, "manifest_digest"),
        )
        if self.valid:
            if (
                self.failure_archive_id is not None
                or self.failure_sequence is not None
                or self.reason is not None
            ):
                raise ValueError("valid archive verification cannot contain failure details")
        elif self.failure_archive_id is None or self.reason is None or not self.reason.strip():
            raise ValueError("invalid archive verification requires archive id and reason")


@dataclass(frozen=True, slots=True)
class AuditRetentionPolicy:
    """Conservative policy for archived bundles; deletion is never implicit."""

    keep_last: int = 10
    max_age: timedelta | None = None
    protected_archive_ids: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        if self.keep_last < 0:
            raise ValueError("keep_last cannot be negative")
        if self.max_age is not None and self.max_age <= timedelta(0):
            raise ValueError("max_age must be positive")
        object.__setattr__(
            self,
            "protected_archive_ids",
            frozenset(_normalize_archive_id(value) for value in self.protected_archive_ids),
        )


@dataclass(frozen=True, slots=True)
class AuditRetentionPlan:
    """Reviewable deletion plan that requires digest confirmation before applying."""

    generated_at: datetime
    delete_archive_ids: tuple[str, ...]
    retain_archive_ids: tuple[str, ...]
    reclaimed_bytes: int
    digest: str

    def __post_init__(self) -> None:
        if self.generated_at.tzinfo is None:
            raise ValueError("generated_at must be timezone-aware")
        if self.reclaimed_bytes < 0:
            raise ValueError("reclaimed_bytes cannot be negative")
        object.__setattr__(
            self,
            "delete_archive_ids",
            tuple(_normalize_archive_id(value) for value in self.delete_archive_ids),
        )
        object.__setattr__(
            self,
            "retain_archive_ids",
            tuple(_normalize_archive_id(value) for value in self.retain_archive_ids),
        )
        object.__setattr__(self, "digest", _normalize_digest(self.digest, "retention plan digest"))


@dataclass(frozen=True, slots=True)
class AuditRetentionResult:
    """Result of applying a confirmed retention plan."""

    deleted_archive_ids: tuple[str, ...]
    reclaimed_bytes: int


@dataclass(frozen=True, slots=True)
class _ManifestDocument:
    manifest: AuditArchiveManifest
    path: Path


def _record_document(record: AuditRecord) -> dict[str, object]:
    seal = record.seal
    return {
        "sequence": record.sequence,
        "recorded_at": record.recorded_at.isoformat(),
        "previous_digest": record.previous_digest,
        "digest": record.digest,
        "event": {
            "id": str(record.event.id),
            "name": record.event.name,
            "source": record.event.source,
            "category": record.event.category.value,
            "action": record.event.action,
            "resource": record.event.resource,
            "actor": record.event.actor,
            "outcome": record.event.outcome.value,
            "severity": record.event.severity.value,
            "details": _portable(record.event.details),
            "occurred_at": record.event.occurred_at.isoformat(),
            "correlation_id": record.event.correlation_id,
            "causation_id": None
            if record.event.causation_id is None
            else str(record.event.causation_id),
        },
        "seal": None
        if seal is None
        else {
            "key": {
                "name": seal.key.name,
                "provider": seal.key.provider,
                "version": seal.key.version,
            },
            "algorithm": seal.algorithm,
            "signature": base64.b64encode(seal.signature).decode("ascii"),
        },
    }


def _record_bytes(records: Iterable[AuditRecord]) -> bytes:
    return b"".join(_canonical_json(_record_document(record)) + b"\n" for record in records)


def _parse_datetime(value: object, label: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be text")
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError(f"{label} must be timezone-aware")
    return parsed


def _decode_record(document: object) -> AuditRecord:
    if not isinstance(document, dict):
        raise ValueError("archive record must be an object")
    event_document = document.get("event")
    if not isinstance(event_document, dict):
        raise ValueError("archive event must be an object")
    details = event_document.get("details")
    if not isinstance(details, dict):
        raise ValueError("archive event details must be an object")
    causation_id = event_document.get("causation_id")
    event = AuditEvent(
        id=UUID(str(event_document["id"])),
        name=str(event_document["name"]),
        source=str(event_document["source"]),
        category=AuditCategory(str(event_document["category"])),
        action=str(event_document["action"]),
        resource=str(event_document["resource"]),
        actor=str(event_document["actor"]),
        outcome=AuditOutcome(str(event_document["outcome"])),
        severity=AuditSeverity(str(event_document["severity"])),
        details=MappingProxyType(details),
        occurred_at=_parse_datetime(event_document["occurred_at"], "occurred_at"),
        correlation_id=None
        if event_document.get("correlation_id") is None
        else str(event_document["correlation_id"]),
        causation_id=None if causation_id is None else UUID(str(causation_id)),
    )
    seal_document = document.get("seal")
    seal = None
    if seal_document is not None:
        if not isinstance(seal_document, dict):
            raise ValueError("archive seal must be an object")
        key_document = seal_document.get("key")
        if not isinstance(key_document, dict):
            raise ValueError("archive seal key must be an object")
        version = key_document.get("version")
        seal = AuditSeal(
            key=KeyRef(
                name=str(key_document["name"]),
                provider=str(key_document["provider"]),
                version=None if version is None else int(version),
            ),
            algorithm=str(seal_document["algorithm"]),
            signature=base64.b64decode(str(seal_document["signature"]), validate=True),
        )
    return AuditRecord(
        event=event,
        sequence=int(document["sequence"]),
        recorded_at=_parse_datetime(document["recorded_at"], "recorded_at"),
        previous_digest=str(document["previous_digest"]),
        digest=str(document["digest"]),
        seal=seal,
    )


def _manifest_payload(manifest: AuditArchiveManifest) -> dict[str, object]:
    return {
        "schema_version": manifest.schema_version,
        "archive_id": manifest.archive_id,
        "created_at": manifest.created_at.isoformat(),
        "first_sequence": manifest.first_sequence,
        "last_sequence": manifest.last_sequence,
        "record_count": manifest.record_count,
        "anchor_digest": manifest.anchor_digest,
        "head_digest": manifest.head_digest,
        "payload_digest": manifest.payload_digest,
        "artifact_digest": manifest.artifact_digest,
        "previous_manifest_digest": manifest.previous_manifest_digest,
        "compression": manifest.compression.value,
        "artifact_name": manifest.artifact_name,
    }


def canonical_archive_manifest_bytes(manifest: AuditArchiveManifest) -> bytes:
    """Return canonical bytes covered by ``manifest.manifest_digest``."""

    return _canonical_json(_manifest_payload(manifest))


def compute_archive_manifest_digest(manifest: AuditArchiveManifest) -> str:
    """Compute the SHA-256 digest of one archive manifest payload."""

    return _digest(canonical_archive_manifest_bytes(manifest))


def _manifest_document(manifest: AuditArchiveManifest) -> bytes:
    document = _manifest_payload(manifest)
    document["manifest_digest"] = manifest.manifest_digest
    return _canonical_json(document) + b"\n"


def _decode_manifest(document: object) -> AuditArchiveManifest:
    if not isinstance(document, dict):
        raise ValueError("archive manifest must be an object")
    return AuditArchiveManifest(
        schema_version=int(document["schema_version"]),
        archive_id=str(document["archive_id"]),
        created_at=_parse_datetime(document["created_at"], "created_at"),
        first_sequence=int(document["first_sequence"]),
        last_sequence=int(document["last_sequence"]),
        record_count=int(document["record_count"]),
        anchor_digest=str(document["anchor_digest"]),
        head_digest=str(document["head_digest"]),
        payload_digest=str(document["payload_digest"]),
        artifact_digest=str(document["artifact_digest"]),
        previous_manifest_digest=str(document["previous_manifest_digest"]),
        compression=AuditArchiveCompression(str(document["compression"])),
        artifact_name=str(document["artifact_name"]),
        manifest_digest=str(document["manifest_digest"]),
    )


def _compress(payload: bytes, compression: AuditArchiveCompression) -> bytes:
    if compression is AuditArchiveCompression.NONE:
        return payload
    import io

    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode="wb", mtime=0) as compressed:
        compressed.write(payload)
    return buffer.getvalue()


def _decompress(artifact: bytes, compression: AuditArchiveCompression) -> bytes:
    if compression is AuditArchiveCompression.NONE:
        return artifact
    return gzip.decompress(artifact)


def _retention_plan_digest(plan: AuditRetentionPlan) -> str:
    payload = {
        "generated_at": plan.generated_at.isoformat(),
        "delete_archive_ids": list(plan.delete_archive_ids),
        "retain_archive_ids": list(plan.retain_archive_ids),
        "reclaimed_bytes": plan.reclaimed_bytes,
    }
    return _digest(_canonical_json(payload))


class AuditArchiveManager:
    """Publish canonical archive segments and manage their retention safely."""

    def __init__(self, directory: str | Path) -> None:
        path = Path(directory).expanduser()
        if path.exists() and not path.is_dir():
            raise ValueError("archive directory must be a directory")
        path.mkdir(parents=True, exist_ok=True)
        self._directory = path.resolve()
        self._lock = asyncio.Lock()

    @property
    def directory(self) -> Path:
        return self._directory

    async def export_segment(
        self,
        store: AuditStore,
        *,
        start_sequence: int,
        end_sequence: int,
        compression: AuditArchiveCompression = AuditArchiveCompression.GZIP,
        created_at: datetime | None = None,
    ) -> AuditArchiveResult:
        """Export one exact contiguous sequence range using atomic file publication."""

        if start_sequence <= 0 or end_sequence < start_sequence:
            raise ValueError("archive sequence bounds are invalid")
        compression = AuditArchiveCompression(compression)
        created_at = datetime.now(UTC) if created_at is None else created_at
        if created_at.tzinfo is None:
            raise ValueError("created_at must be timezone-aware")

        async with self._lock:
            archive_id = f"audit-{start_sequence:020d}-{end_sequence:020d}"
            artifact_name = archive_id + _PAYLOAD_SUFFIX
            if compression is AuditArchiveCompression.GZIP:
                artifact_name += _GZIP_SUFFIX
            artifact_path = self._directory / artifact_name
            manifest_path = self._directory / f"{archive_id}{_MANIFEST_SUFFIX}"
            if artifact_path.exists() or manifest_path.exists():
                raise AuditArchiveExistsError(f"archive already exists: {archive_id}")

            records = await self._read_exact(store, start_sequence, end_sequence)
            self._validate_records(records, start_sequence, end_sequence)
            previous = self._latest_manifest()
            if previous is None:
                previous_manifest_digest = AUDIT_GENESIS_DIGEST
            else:
                if start_sequence != previous.manifest.last_sequence + 1:
                    raise AuditArchiveError(
                        "new archive must start immediately after the latest archived sequence"
                    )
                if records[0].previous_digest != previous.manifest.head_digest:
                    raise AuditArchiveError(
                        "new archive does not continue the previous archive head"
                    )
                previous_manifest_digest = previous.manifest.manifest_digest

            payload = _record_bytes(records)
            artifact = _compress(payload, compression)

            provisional = AuditArchiveManifest(
                archive_id=archive_id,
                created_at=created_at,
                first_sequence=start_sequence,
                last_sequence=end_sequence,
                record_count=len(records),
                anchor_digest=records[0].previous_digest,
                head_digest=records[-1].digest,
                payload_digest=_digest(payload),
                artifact_digest=_digest(artifact),
                previous_manifest_digest=previous_manifest_digest,
                compression=compression,
                artifact_name=artifact_name,
                manifest_digest=AUDIT_GENESIS_DIGEST,
            )
            manifest = AuditArchiveManifest(
                archive_id=provisional.archive_id,
                created_at=provisional.created_at,
                first_sequence=provisional.first_sequence,
                last_sequence=provisional.last_sequence,
                record_count=provisional.record_count,
                anchor_digest=provisional.anchor_digest,
                head_digest=provisional.head_digest,
                payload_digest=provisional.payload_digest,
                artifact_digest=provisional.artifact_digest,
                previous_manifest_digest=provisional.previous_manifest_digest,
                compression=provisional.compression,
                artifact_name=provisional.artifact_name,
                manifest_digest=compute_archive_manifest_digest(provisional),
            )
            self._atomic_write(artifact_path, artifact)
            try:
                self._atomic_write(manifest_path, _manifest_document(manifest))
            except Exception:
                artifact_path.unlink(missing_ok=True)
                raise
            return AuditArchiveResult(manifest, manifest_path, artifact_path)

    async def rotate(
        self,
        store: AuditStore,
        *,
        segment_records: int,
        include_partial: bool = False,
        compression: AuditArchiveCompression = AuditArchiveCompression.GZIP,
    ) -> tuple[AuditArchiveResult, ...]:
        """Export every not-yet-archived full segment from the live store."""

        if segment_records <= 0:
            raise ValueError("segment_records must be positive")
        latest = self._latest_manifest()
        start = 1 if latest is None else latest.manifest.last_sequence + 1
        snapshot = await store.snapshot()
        head = snapshot.head_sequence
        if head is None or start > head:
            return ()
        results: list[AuditArchiveResult] = []
        while start <= head:
            end = min(start + segment_records - 1, head)
            if end - start + 1 < segment_records and not include_partial:
                break
            results.append(
                await self.export_segment(
                    store,
                    start_sequence=start,
                    end_sequence=end,
                    compression=compression,
                )
            )
            start = end + 1
        return tuple(results)

    async def verify_archive(
        self,
        manifest_path: str | Path,
        *,
        signer: AuditSigner | None = None,
    ) -> AuditArchiveVerification:
        """Verify one manifest, artifact, record chain, and optional external seals."""

        try:
            document = self._read_manifest(Path(manifest_path))
            manifest = document.manifest
            if compute_archive_manifest_digest(manifest) != manifest.manifest_digest:
                return self._invalid(manifest, "manifest digest mismatch")
            artifact_path = document.path.parent / manifest.artifact_name
            artifact = artifact_path.read_bytes()
            if _digest(artifact) != manifest.artifact_digest:
                return self._invalid(manifest, "archive artifact digest mismatch")
            try:
                payload = _decompress(artifact, manifest.compression)
            except (OSError, EOFError) as exception:
                return self._invalid(
                    manifest, f"archive decompression failed: {type(exception).__name__}"
                )
            if _digest(payload) != manifest.payload_digest:
                return self._invalid(manifest, "archive payload digest mismatch")
            records = self._decode_payload(payload)
            if len(records) != manifest.record_count:
                return self._invalid(manifest, "archive record count mismatch")
            signatures_checked = 0
            previous_digest = manifest.anchor_digest
            for offset, record in enumerate(records):
                expected_sequence = manifest.first_sequence + offset
                if record.sequence != expected_sequence:
                    return self._invalid(
                        manifest,
                        f"sequence mismatch: expected {expected_sequence}, found {record.sequence}",
                        failure_sequence=record.sequence,
                        checked_records=offset + 1,
                        signatures_checked=signatures_checked,
                    )
                if record.previous_digest != previous_digest:
                    return self._invalid(
                        manifest,
                        "previous digest link mismatch",
                        failure_sequence=record.sequence,
                        checked_records=offset + 1,
                        signatures_checked=signatures_checked,
                    )
                expected_digest = compute_audit_digest(
                    record.event,
                    sequence=record.sequence,
                    recorded_at=record.recorded_at,
                    previous_digest=record.previous_digest,
                )
                if record.digest != expected_digest:
                    return self._invalid(
                        manifest,
                        "record digest mismatch",
                        failure_sequence=record.sequence,
                        checked_records=offset + 1,
                        signatures_checked=signatures_checked,
                    )
                if record.seal is not None:
                    if signer is None:
                        return self._invalid(
                            manifest,
                            "signature verifier unavailable",
                            failure_sequence=record.sequence,
                            checked_records=offset + 1,
                            signatures_checked=signatures_checked,
                        )
                    try:
                        valid = signer.verify(
                            bytes.fromhex(record.digest),
                            record.seal.signature,
                            key=record.seal.key,
                        )
                        if inspect.isawaitable(valid):
                            valid = await valid
                    except asyncio.CancelledError:
                        raise
                    except Exception as exception:
                        raise AuditSignerError(
                            "archive signature verification failed"
                        ) from exception
                    if not valid:
                        return self._invalid(
                            manifest,
                            "external signature mismatch",
                            failure_sequence=record.sequence,
                            checked_records=offset + 1,
                            signatures_checked=signatures_checked,
                        )
                    signatures_checked += 1
                previous_digest = record.digest
            if not records or records[-1].sequence != manifest.last_sequence:
                return self._invalid(manifest, "archive sequence bounds mismatch")
            if previous_digest != manifest.head_digest:
                return self._invalid(manifest, "archive head digest mismatch")
            return AuditArchiveVerification(
                valid=True,
                checked_archives=1,
                checked_records=len(records),
                head_digest=manifest.head_digest,
                manifest_digest=manifest.manifest_digest,
                signatures_checked=signatures_checked,
            )
        except asyncio.CancelledError:
            raise
        except AuditSignerError:
            raise
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exception:
            archive_id = Path(manifest_path).name.removesuffix(_MANIFEST_SUFFIX)
            return AuditArchiveVerification(
                valid=False,
                checked_archives=0,
                checked_records=0,
                head_digest=AUDIT_GENESIS_DIGEST,
                manifest_digest=AUDIT_GENESIS_DIGEST,
                failure_archive_id=archive_id or "unknown",
                reason=f"archive cannot be decoded: {type(exception).__name__}",
            )

    async def verify_chain(
        self,
        *,
        signer: AuditSigner | None = None,
    ) -> AuditArchiveVerification:
        """Verify every archive and cross-segment manifest/hash continuity."""

        manifests = self._manifest_documents()
        if not manifests:
            return AuditArchiveVerification(
                valid=True,
                checked_archives=0,
                checked_records=0,
                head_digest=AUDIT_GENESIS_DIGEST,
                manifest_digest=AUDIT_GENESIS_DIGEST,
            )
        checked_archives = 0
        checked_records = 0
        signatures_checked = 0
        first_manifest = manifests[0].manifest
        previous_head = first_manifest.anchor_digest
        previous_manifest = first_manifest.previous_manifest_digest
        previous_last = first_manifest.first_sequence - 1
        for document in manifests:
            manifest = document.manifest
            if manifest.first_sequence != previous_last + 1:
                return self._invalid_chain(
                    manifest,
                    checked_archives,
                    checked_records,
                    signatures_checked,
                    previous_head,
                    previous_manifest,
                    "archive sequence continuity mismatch",
                )
            if manifest.anchor_digest != previous_head:
                return self._invalid_chain(
                    manifest,
                    checked_archives,
                    checked_records,
                    signatures_checked,
                    previous_head,
                    previous_manifest,
                    "archive head continuity mismatch",
                )
            if manifest.previous_manifest_digest != previous_manifest:
                return self._invalid_chain(
                    manifest,
                    checked_archives,
                    checked_records,
                    signatures_checked,
                    previous_head,
                    previous_manifest,
                    "manifest chain continuity mismatch",
                )
            result = await self.verify_archive(document.path, signer=signer)
            if not result.valid:
                return AuditArchiveVerification(
                    valid=False,
                    checked_archives=checked_archives + result.checked_archives,
                    checked_records=checked_records + result.checked_records,
                    head_digest=previous_head,
                    manifest_digest=previous_manifest,
                    signatures_checked=signatures_checked + result.signatures_checked,
                    failure_archive_id=result.failure_archive_id,
                    failure_sequence=result.failure_sequence,
                    reason=result.reason,
                )
            checked_archives += 1
            checked_records += result.checked_records
            signatures_checked += result.signatures_checked
            previous_last = manifest.last_sequence
            previous_head = manifest.head_digest
            previous_manifest = manifest.manifest_digest
        return AuditArchiveVerification(
            valid=True,
            checked_archives=checked_archives,
            checked_records=checked_records,
            head_digest=previous_head,
            manifest_digest=previous_manifest,
            signatures_checked=signatures_checked,
        )

    def plan_retention(
        self,
        policy: AuditRetentionPolicy,
        *,
        now: datetime | None = None,
    ) -> AuditRetentionPlan:
        """Build a reviewable retention plan without deleting any files."""

        now = datetime.now(UTC) if now is None else now
        if now.tzinfo is None:
            raise ValueError("now must be timezone-aware")
        documents = self._manifest_documents()
        protected = policy.protected_archive_ids
        keep_from = max(0, len(documents) - policy.keep_last)
        delete: list[str] = []
        reclaimed = 0
        cutoff = 0
        for index, document in enumerate(documents):
            manifest = document.manifest
            too_old = policy.max_age is None or now - manifest.created_at >= policy.max_age
            if index >= keep_from or manifest.archive_id in protected or not too_old:
                break
            delete.append(manifest.archive_id)
            artifact_path = document.path.parent / manifest.artifact_name
            reclaimed += document.path.stat().st_size
            if artifact_path.exists():
                reclaimed += artifact_path.stat().st_size
            cutoff = index + 1
        retain = [document.manifest.archive_id for document in documents[cutoff:]]
        payload = {
            "generated_at": now.isoformat(),
            "delete_archive_ids": delete,
            "retain_archive_ids": retain,
            "reclaimed_bytes": reclaimed,
        }
        return AuditRetentionPlan(
            generated_at=now,
            delete_archive_ids=tuple(delete),
            retain_archive_ids=tuple(retain),
            reclaimed_bytes=reclaimed,
            digest=_digest(_canonical_json(payload)),
        )

    async def apply_retention(
        self,
        plan: AuditRetentionPlan,
        *,
        confirmation_digest: str,
    ) -> AuditRetentionResult:
        """Apply a plan only after exact digest confirmation and chain validation."""

        if _retention_plan_digest(plan) != plan.digest:
            raise AuditRetentionConfirmationError("retention plan digest is invalid")
        if _normalize_digest(confirmation_digest, "confirmation_digest") != plan.digest:
            raise AuditRetentionConfirmationError(
                "retention confirmation digest does not match plan"
            )
        async with self._lock:
            chain = await self.verify_chain()
            if not chain.valid:
                raise AuditArchiveVerificationError(
                    f"refusing retention because archive verification failed: {chain.reason}"
                )
            deleted: list[str] = []
            reclaimed = 0
            for archive_id in plan.delete_archive_ids:
                manifest_path = self._directory / f"{archive_id}{_MANIFEST_SUFFIX}"
                if not manifest_path.exists():
                    raise AuditRetentionConfirmationError(
                        f"retention plan is stale; manifest is missing: {archive_id}"
                    )
                document = self._read_manifest(manifest_path)
                artifact_path = self._directory / document.manifest.artifact_name
                size = manifest_path.stat().st_size
                if artifact_path.exists():
                    size += artifact_path.stat().st_size
                artifact_path.unlink(missing_ok=False)
                manifest_path.unlink(missing_ok=False)
                deleted.append(archive_id)
                reclaimed += size
            return AuditRetentionResult(tuple(deleted), reclaimed)

    async def _read_exact(
        self,
        store: AuditStore,
        start_sequence: int,
        end_sequence: int,
    ) -> tuple[AuditRecord, ...]:
        records: list[AuditRecord] = []
        cursor = start_sequence
        while cursor <= end_sequence:
            limit = min(1000, end_sequence - cursor + 1)
            batch = await store.read(
                AuditQuery(start_sequence=cursor, end_sequence=end_sequence, limit=limit)
            )
            if not batch:
                break
            records.extend(batch)
            cursor = batch[-1].sequence + 1
        return tuple(records)

    @staticmethod
    def _validate_records(
        records: tuple[AuditRecord, ...],
        start_sequence: int,
        end_sequence: int,
    ) -> None:
        expected_count = end_sequence - start_sequence + 1
        if len(records) != expected_count:
            raise AuditArchiveError(
                "archive range is incomplete: "
                f"expected {expected_count} records, found {len(records)}"
            )
        previous_digest = records[0].previous_digest
        for expected_sequence, record in enumerate(records, start=start_sequence):
            if record.sequence != expected_sequence:
                raise AuditArchiveError("archive records are not contiguous")
            if record.previous_digest != previous_digest:
                raise AuditArchiveError("archive record chain is not contiguous")
            previous_digest = record.digest

    def _latest_manifest(self) -> _ManifestDocument | None:
        documents = self._manifest_documents()
        return None if not documents else documents[-1]

    def _manifest_documents(self) -> tuple[_ManifestDocument, ...]:
        documents = tuple(
            self._read_manifest(path)
            for path in sorted(self._directory.glob(f"*{_MANIFEST_SUFFIX}"))
        )
        return tuple(sorted(documents, key=lambda item: item.manifest.first_sequence))

    @staticmethod
    def _read_manifest(path: Path) -> _ManifestDocument:
        document = json.loads(path.read_text(encoding="utf-8"))
        return _ManifestDocument(_decode_manifest(document), path.resolve())

    @staticmethod
    def _decode_payload(payload: bytes) -> tuple[AuditRecord, ...]:
        if not payload:
            return ()
        lines = payload.splitlines()
        return tuple(_decode_record(json.loads(line)) for line in lines)

    @staticmethod
    def _atomic_write(path: Path, content: bytes) -> None:
        temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
        try:
            with temporary.open("xb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)

    @staticmethod
    def _invalid(
        manifest: AuditArchiveManifest,
        reason: str,
        *,
        failure_sequence: int | None = None,
        checked_records: int = 0,
        signatures_checked: int = 0,
    ) -> AuditArchiveVerification:
        return AuditArchiveVerification(
            valid=False,
            checked_archives=1,
            checked_records=checked_records,
            head_digest=manifest.anchor_digest,
            manifest_digest=manifest.previous_manifest_digest,
            signatures_checked=signatures_checked,
            failure_archive_id=manifest.archive_id,
            failure_sequence=failure_sequence,
            reason=reason,
        )

    @staticmethod
    def _invalid_chain(
        manifest: AuditArchiveManifest,
        checked_archives: int,
        checked_records: int,
        signatures_checked: int,
        previous_head: str,
        previous_manifest: str,
        reason: str,
    ) -> AuditArchiveVerification:
        return AuditArchiveVerification(
            valid=False,
            checked_archives=checked_archives,
            checked_records=checked_records,
            head_digest=previous_head,
            manifest_digest=previous_manifest,
            signatures_checked=signatures_checked,
            failure_archive_id=manifest.archive_id,
            failure_sequence=manifest.first_sequence,
            reason=reason,
        )
