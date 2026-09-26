"""Zero-effect RFC-0039 workspace patch commit revalidation contracts."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from uuid import UUID

from phoenix_os.agent.checkout_patch_preparation import (
    MAX_CHECKOUT_PATCH_AFFECTED_LINES,
    MAX_CHECKOUT_PATCH_TARGET_BYTES,
    CheckoutPatchPreparation,
)
from phoenix_os.agent.checkout_patch_security import CheckoutPatchSecurityMetadata
from phoenix_os.agent.checkout_workspace import (
    CheckoutReadResult,
    RegisteredDevelopmentCheckout,
)
from phoenix_os.agent.contracts import AgentRunId, AgentStepId, ToolCallId

_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_UTF8_BOM = b"\xef\xbb\xbf"


@dataclass(frozen=True, slots=True)
class CheckoutPatchCommitTicket:
    """Content-free freshness binding for one exact prepared patch commit."""

    run_id: AgentRunId
    step_id: AgentStepId
    call_id: ToolCallId
    workspace_id: UUID
    registration_generation: int
    logical_path: str
    root_identity: str
    file_identity: str
    before_content_digest: str
    after_content_digest: str
    preparation_digest: str
    security_metadata_fingerprint: str
    changed_line_count: int
    current_byte_length: int
    freshness_digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.run_id, AgentRunId):
            raise TypeError("run_id must be AgentRunId")
        if not isinstance(self.step_id, AgentStepId):
            raise TypeError("step_id must be AgentStepId")
        if not isinstance(self.call_id, ToolCallId):
            raise TypeError("call_id must be ToolCallId")
        if not isinstance(self.workspace_id, UUID):
            raise TypeError("workspace_id must be UUID")
        if (
            isinstance(self.registration_generation, bool)
            or not isinstance(self.registration_generation, int)
            or self.registration_generation < 1
        ):
            raise ValueError("registration_generation must be positive")
        if not isinstance(self.logical_path, str) or not self.logical_path:
            raise ValueError("logical_path must be non-empty")
        for label, value in (
            ("root_identity", self.root_identity),
            ("file_identity", self.file_identity),
            ("before_content_digest", self.before_content_digest),
            ("after_content_digest", self.after_content_digest),
            ("preparation_digest", self.preparation_digest),
            ("security_metadata_fingerprint", self.security_metadata_fingerprint),
            ("freshness_digest", self.freshness_digest),
        ):
            _require_digest(value, label=label)
        if (
            isinstance(self.changed_line_count, bool)
            or not isinstance(self.changed_line_count, int)
            or not 1 <= self.changed_line_count <= MAX_CHECKOUT_PATCH_AFFECTED_LINES
        ):
            raise ValueError("changed_line_count is out of bounds")
        if (
            isinstance(self.current_byte_length, bool)
            or not isinstance(self.current_byte_length, int)
            or not 0 <= self.current_byte_length <= MAX_CHECKOUT_PATCH_TARGET_BYTES
        ):
            raise ValueError("current_byte_length is out of bounds")


def revalidate_checkout_patch_commit(
    registration: RegisteredDevelopmentCheckout,
    current_read_result: CheckoutReadResult,
    preparation: CheckoutPatchPreparation,
    *,
    security_metadata: CheckoutPatchSecurityMetadata,
    run_id: AgentRunId,
    step_id: AgentStepId,
    call_id: ToolCallId,
) -> CheckoutPatchCommitTicket:
    """Revalidate exact current freshness immediately before a later effect boundary."""

    if not isinstance(registration, RegisteredDevelopmentCheckout):
        raise TypeError("registration must be RegisteredDevelopmentCheckout")
    if not isinstance(current_read_result, CheckoutReadResult):
        raise TypeError("current_read_result must be CheckoutReadResult")
    if not isinstance(preparation, CheckoutPatchPreparation):
        raise TypeError("preparation must be CheckoutPatchPreparation")
    if not isinstance(security_metadata, CheckoutPatchSecurityMetadata):
        raise TypeError("security_metadata must be CheckoutPatchSecurityMetadata")
    if not isinstance(run_id, AgentRunId):
        raise TypeError("run_id must be AgentRunId")
    if not isinstance(step_id, AgentStepId):
        raise TypeError("step_id must be AgentStepId")
    if not isinstance(call_id, ToolCallId):
        raise TypeError("call_id must be ToolCallId")

    if (
        preparation.run_id != run_id
        or preparation.step_id != step_id
        or preparation.call_id != call_id
    ):
        raise ValueError("patch preparation invocation binding is stale")

    snapshot = current_read_result.snapshot
    if snapshot.run_id != run_id:
        raise ValueError("current patch snapshot run binding is stale")
    if (
        registration.workspace_id != preparation.workspace_id
        or registration.generation != preparation.registration_generation
        or registration.root_identity != preparation.root_identity
    ):
        raise ValueError("patch checkout registration changed")
    if (
        snapshot.workspace_id != preparation.workspace_id
        or snapshot.registration_generation != preparation.registration_generation
        or snapshot.logical_path != preparation.logical_path
        or snapshot.root_identity != preparation.root_identity
    ):
        raise ValueError("current patch snapshot identity changed")
    if snapshot.file_identity != preparation.file_identity:
        raise ValueError("current patch file identity changed")
    if snapshot.content_digest != preparation.before_content_digest:
        raise ValueError("current patch base content changed")
    if not any(
        _within_prefix(preparation.logical_path, prefix) for prefix in registration.patch_prefixes
    ):
        raise ValueError("patch target is outside patch_prefixes")

    if security_metadata.fingerprint != preparation.security_metadata_fingerprint:
        raise ValueError("current patch security metadata changed")

    source = _strict_utf8(current_read_result.text, label="current checkout source")
    if len(source) != snapshot.byte_length:
        raise ValueError("current patch byte length changed")
    if len(source) > MAX_CHECKOUT_PATCH_TARGET_BYTES:
        raise ValueError("current patch target exceeds supported bound")
    if _digest(source) != snapshot.content_digest:
        raise ValueError("current patch content digest is inconsistent")
    if source.startswith(_UTF8_BOM):
        raise ValueError("current patch source must be UTF-8 without BOM")
    if b"\x00" in source:
        raise ValueError("current patch source cannot contain NUL")

    candidate = preparation.candidate_bytes
    if not isinstance(candidate, bytes):
        raise TypeError("prepared candidate must be bytes")
    if len(candidate) > MAX_CHECKOUT_PATCH_TARGET_BYTES:
        raise ValueError("prepared candidate exceeds supported bound")
    if candidate.startswith(_UTF8_BOM):
        raise ValueError("prepared candidate must be UTF-8 without BOM")
    if b"\x00" in candidate:
        raise ValueError("prepared candidate cannot contain NUL")
    try:
        candidate.decode("utf-8")
    except UnicodeDecodeError as exception:
        raise ValueError("prepared candidate is not valid UTF-8") from exception
    if _digest(candidate) != preparation.after_content_digest:
        raise ValueError("prepared candidate digest changed")
    if preparation.after_content_digest == preparation.before_content_digest:
        raise ValueError("prepared patch has no effect")
    if candidate == source:
        raise ValueError("prepared candidate unexpectedly equals current source")

    _require_digest(preparation.preparation_digest, label="preparation_digest")

    freshness_record = {
        "schema": "rfc0039.workspace.patch.commit-preflight.v1",
        "run_id": str(run_id),
        "step_id": str(step_id),
        "call_id": str(call_id),
        "workspace_id": str(preparation.workspace_id),
        "registration_generation": preparation.registration_generation,
        "logical_path": preparation.logical_path,
        "root_identity": preparation.root_identity,
        "file_identity": preparation.file_identity,
        "before_content_digest": preparation.before_content_digest,
        "after_content_digest": preparation.after_content_digest,
        "preparation_digest": preparation.preparation_digest,
        "security_metadata_fingerprint": preparation.security_metadata_fingerprint,
        "changed_line_count": preparation.changed_line_count,
        "current_byte_length": snapshot.byte_length,
    }
    freshness_digest = _digest(_canonical_json_bytes(freshness_record))

    return CheckoutPatchCommitTicket(
        run_id=run_id,
        step_id=step_id,
        call_id=call_id,
        workspace_id=preparation.workspace_id,
        registration_generation=preparation.registration_generation,
        logical_path=preparation.logical_path,
        root_identity=preparation.root_identity,
        file_identity=preparation.file_identity,
        before_content_digest=preparation.before_content_digest,
        after_content_digest=preparation.after_content_digest,
        preparation_digest=preparation.preparation_digest,
        security_metadata_fingerprint=preparation.security_metadata_fingerprint,
        changed_line_count=preparation.changed_line_count,
        current_byte_length=snapshot.byte_length,
        freshness_digest=freshness_digest,
    )


def _strict_utf8(value: str, *, label: str) -> bytes:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string")
    try:
        return value.encode("utf-8")
    except UnicodeEncodeError as exception:
        raise ValueError(f"{label} is not strict UTF-8") from exception


def _require_digest(value: str, *, label: str) -> None:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string")
    if _DIGEST_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{label} must be a canonical sha256 digest")


def _digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _within_prefix(logical_path: str, prefix: str) -> bool:
    return logical_path == prefix or logical_path.startswith(prefix + "/")
