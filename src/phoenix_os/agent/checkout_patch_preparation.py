"""Zero-effect deterministic RFC-0039 workspace patch preparation primitives."""

from __future__ import annotations

import difflib
import hashlib
import json
import re
from dataclasses import dataclass, field
from uuid import UUID

from phoenix_os.agent.checkout_patch_security import CheckoutPatchSecurityMetadata
from phoenix_os.agent.checkout_workspace import (
    MAX_CHECKOUT_TEXT_READ_BYTES,
    CheckoutFileSnapshot,
    CheckoutReadResult,
    RegisteredDevelopmentCheckout,
)
from phoenix_os.agent.contracts import AgentRunId, AgentStepId, ToolCallId

MAX_CHECKOUT_PATCH_TARGET_BYTES = MAX_CHECKOUT_TEXT_READ_BYTES
MAX_CHECKOUT_PATCH_REQUEST_BYTES = 262_144
MAX_CHECKOUT_PATCH_EDITS = 64
MAX_CHECKOUT_PATCH_REPLACEMENT_BYTES = 262_144
MAX_CHECKOUT_PATCH_AFFECTED_LINES = 2_000
MAX_CHECKOUT_PATCH_DIFF_BYTES = 262_144

_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_UTF8_BOM = b"\xef\xbb\xbf"


@dataclass(frozen=True, slots=True)
class CheckoutPatchEdit:
    """One ordered half-open UTF-8 byte edit with exact expected old text."""

    start_byte: int
    end_byte: int
    expected_text: str
    replacement_text: str

    def __post_init__(self) -> None:
        for label, value in (("start_byte", self.start_byte), ("end_byte", self.end_byte)):
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{label} must be an int")
            if value < 0:
                raise ValueError(f"{label} cannot be negative")
        if self.end_byte < self.start_byte:
            raise ValueError("end_byte cannot precede start_byte")
        expected = _strict_utf8(self.expected_text, label="expected_text")
        replacement = _strict_utf8(self.replacement_text, label="replacement_text")
        if b"\x00" in expected or b"\x00" in replacement:
            raise ValueError("patch edit text cannot contain NUL")
        if len(replacement) > MAX_CHECKOUT_PATCH_REPLACEMENT_BYTES:
            raise ValueError("replacement_text exceeds supported bound")
        if expected == replacement:
            raise ValueError("patch edit must change content")


@dataclass(frozen=True, slots=True)
class CheckoutPatchPreparationRequest:
    """Current-run zero-effect patch preparation request bound to one read snapshot."""

    run_id: AgentRunId
    step_id: AgentStepId
    call_id: ToolCallId
    snapshot: CheckoutFileSnapshot
    base_content_digest: str
    edits: tuple[CheckoutPatchEdit, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.run_id, AgentRunId):
            raise TypeError("run_id must be AgentRunId")
        if not isinstance(self.step_id, AgentStepId):
            raise TypeError("step_id must be AgentStepId")
        if not isinstance(self.call_id, ToolCallId):
            raise TypeError("call_id must be ToolCallId")
        if not isinstance(self.snapshot, CheckoutFileSnapshot):
            raise TypeError("snapshot must be CheckoutFileSnapshot")
        if self.snapshot.run_id != self.run_id:
            raise ValueError("snapshot run_id does not match request")
        _require_digest(self.base_content_digest, label="base_content_digest")

        edits = tuple(self.edits)
        if not 1 <= len(edits) <= MAX_CHECKOUT_PATCH_EDITS:
            raise ValueError("patch edit count is out of bounds")
        if any(not isinstance(edit, CheckoutPatchEdit) for edit in edits):
            raise TypeError("edits must contain CheckoutPatchEdit values")

        previous_start = -1
        previous_end = -1
        replacement_bytes = 0
        for edit in edits:
            if edit.start_byte <= previous_start:
                raise ValueError("patch edits must be strictly ordered")
            if edit.start_byte < previous_end:
                raise ValueError("patch edits must not overlap")
            previous_start = edit.start_byte
            previous_end = edit.end_byte
            replacement_bytes += len(_strict_utf8(edit.replacement_text, label="replacement_text"))

        if replacement_bytes > MAX_CHECKOUT_PATCH_REPLACEMENT_BYTES:
            raise ValueError("aggregate replacement text exceeds supported bound")
        object.__setattr__(self, "edits", edits)

        if len(_canonical_request_bytes(self)) > MAX_CHECKOUT_PATCH_REQUEST_BYTES:
            raise ValueError("patch request exceeds supported bound")


@dataclass(frozen=True, slots=True)
class CheckoutPatchPreparation:
    """Server-prepared content-free binding plus in-memory candidate and trusted diff."""

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
    _candidate_bytes: bytes = field(repr=False, compare=False)
    _unified_diff: str = field(repr=False, compare=False)

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
        for label, value in (
            ("root_identity", self.root_identity),
            ("file_identity", self.file_identity),
            ("before_content_digest", self.before_content_digest),
            ("after_content_digest", self.after_content_digest),
            ("preparation_digest", self.preparation_digest),
            ("security_metadata_fingerprint", self.security_metadata_fingerprint),
        ):
            _require_digest(value, label=label)
        if (
            isinstance(self.changed_line_count, bool)
            or not isinstance(self.changed_line_count, int)
            or not 1 <= self.changed_line_count <= MAX_CHECKOUT_PATCH_AFFECTED_LINES
        ):
            raise ValueError("changed_line_count is out of bounds")
        if not isinstance(self._candidate_bytes, bytes):
            raise TypeError("candidate bytes must be bytes")
        if not isinstance(self._unified_diff, str):
            raise TypeError("unified diff must be a string")

    @property
    def candidate_bytes(self) -> bytes:
        """Return the in-memory candidate for the later controlled commit boundary."""

        return self._candidate_bytes

    @property
    def unified_diff(self) -> str:
        """Return the complete trusted bounded unified diff; never a truncation."""

        return self._unified_diff


def prepare_checkout_patch(
    registration: RegisteredDevelopmentCheckout,
    read_result: CheckoutReadResult,
    request: CheckoutPatchPreparationRequest,
    security_metadata: CheckoutPatchSecurityMetadata,
) -> CheckoutPatchPreparation:
    """Prepare one exact patch entirely in memory without performing a write."""

    if not isinstance(registration, RegisteredDevelopmentCheckout):
        raise TypeError("registration must be RegisteredDevelopmentCheckout")
    if not isinstance(read_result, CheckoutReadResult):
        raise TypeError("read_result must be CheckoutReadResult")
    if not isinstance(request, CheckoutPatchPreparationRequest):
        raise TypeError("request must be CheckoutPatchPreparationRequest")
    if not isinstance(security_metadata, CheckoutPatchSecurityMetadata):
        raise TypeError("security_metadata must be CheckoutPatchSecurityMetadata")

    snapshot = read_result.snapshot
    if request.snapshot != snapshot:
        raise ValueError("patch request snapshot is stale or substituted")
    if request.base_content_digest != snapshot.content_digest:
        raise ValueError("patch base content digest is stale")
    if (
        snapshot.workspace_id != registration.workspace_id
        or snapshot.registration_generation != registration.generation
        or snapshot.root_identity != registration.root_identity
    ):
        raise ValueError("patch snapshot does not match checkout registration")
    if not any(
        _within_prefix(snapshot.logical_path, prefix) for prefix in registration.patch_prefixes
    ):
        raise ValueError("patch target is outside patch_prefixes")

    source = _strict_utf8(read_result.text, label="checkout source")
    if len(source) != snapshot.byte_length:
        raise ValueError("patch source byte length does not match snapshot")
    if len(source) > MAX_CHECKOUT_PATCH_TARGET_BYTES:
        raise ValueError("patch target exceeds supported bound")
    if _digest(source) != snapshot.content_digest:
        raise ValueError("patch source content digest does not match snapshot")
    if source.startswith(_UTF8_BOM):
        raise ValueError("patch source must be UTF-8 without BOM")
    if b"\x00" in source:
        raise ValueError("patch source cannot contain NUL")

    boundaries = _utf8_boundaries(read_result.text)
    pieces: list[bytes] = []
    cursor = 0
    changed_lines = 0
    edit_bindings: list[dict[str, object]] = []

    for edit in request.edits:
        if edit.end_byte > len(source):
            raise ValueError("patch edit range exceeds source length")
        if edit.start_byte not in boundaries or edit.end_byte not in boundaries:
            raise ValueError("patch edit range is not UTF-8 codepoint aligned")

        expected = _strict_utf8(edit.expected_text, label="expected_text")
        replacement = _strict_utf8(edit.replacement_text, label="replacement_text")
        if source[edit.start_byte : edit.end_byte] != expected:
            raise ValueError("patch expected old text does not match source")

        pieces.append(source[cursor : edit.start_byte])
        pieces.append(replacement)
        cursor = edit.end_byte
        changed_lines += _affected_line_count(
            source,
            start=edit.start_byte,
            end=edit.end_byte,
            replacement=replacement,
        )
        if changed_lines > MAX_CHECKOUT_PATCH_AFFECTED_LINES:
            raise ValueError("patch affected-line count exceeds supported bound")

        edit_bindings.append(
            {
                "start_byte": edit.start_byte,
                "end_byte": edit.end_byte,
                "expected_digest": _digest(expected),
                "replacement_digest": _digest(replacement),
                "replacement_byte_length": len(replacement),
            }
        )

    pieces.append(source[cursor:])
    candidate = b"".join(pieces)
    if len(candidate) > MAX_CHECKOUT_PATCH_TARGET_BYTES:
        raise ValueError("patch candidate exceeds supported bound")
    if candidate.startswith(_UTF8_BOM):
        raise ValueError("patch candidate must be UTF-8 without BOM")
    if b"\x00" in candidate:
        raise ValueError("patch candidate cannot contain NUL")

    try:
        candidate_text = candidate.decode("utf-8")
    except UnicodeDecodeError as exception:
        raise ValueError("patch candidate is not valid UTF-8") from exception

    after_digest = _digest(candidate)
    if after_digest == snapshot.content_digest:
        raise ValueError("patch candidate has no effect")

    unified_diff = _trusted_unified_diff(
        logical_path=snapshot.logical_path,
        before=read_result.text,
        after=candidate_text,
    )
    diff_bytes = unified_diff.encode("utf-8")
    if not diff_bytes:
        raise ValueError("patch trusted diff is empty")
    if len(diff_bytes) > MAX_CHECKOUT_PATCH_DIFF_BYTES:
        raise ValueError("patch trusted diff exceeds supported bound")

    preparation_record = {
        "schema": "rfc0039.workspace.patch.preparation.v1",
        "run_id": str(request.run_id),
        "step_id": str(request.step_id),
        "call_id": str(request.call_id),
        "workspace_id": str(snapshot.workspace_id),
        "registration_generation": snapshot.registration_generation,
        "logical_path": snapshot.logical_path,
        "root_identity": snapshot.root_identity,
        "file_identity": snapshot.file_identity,
        "before_content_digest": snapshot.content_digest,
        "after_content_digest": after_digest,
        "security_metadata_fingerprint": security_metadata.fingerprint,
        "changed_line_count": changed_lines,
        "edits": edit_bindings,
    }
    preparation_digest = _digest(_canonical_json_bytes(preparation_record))

    return CheckoutPatchPreparation(
        run_id=request.run_id,
        step_id=request.step_id,
        call_id=request.call_id,
        workspace_id=snapshot.workspace_id,
        registration_generation=snapshot.registration_generation,
        logical_path=snapshot.logical_path,
        root_identity=snapshot.root_identity,
        file_identity=snapshot.file_identity,
        before_content_digest=snapshot.content_digest,
        after_content_digest=after_digest,
        preparation_digest=preparation_digest,
        security_metadata_fingerprint=security_metadata.fingerprint,
        changed_line_count=changed_lines,
        _candidate_bytes=candidate,
        _unified_diff=unified_diff,
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


def _canonical_request_bytes(request: CheckoutPatchPreparationRequest) -> bytes:
    snapshot = request.snapshot
    return _canonical_json_bytes(
        {
            "run_id": str(request.run_id),
            "step_id": str(request.step_id),
            "call_id": str(request.call_id),
            "snapshot": {
                "workspace_id": str(snapshot.workspace_id),
                "registration_generation": snapshot.registration_generation,
                "logical_path": snapshot.logical_path,
                "root_identity": snapshot.root_identity,
                "file_identity": snapshot.file_identity,
                "content_digest": snapshot.content_digest,
                "byte_length": snapshot.byte_length,
            },
            "base_content_digest": request.base_content_digest,
            "edits": [
                {
                    "start_byte": edit.start_byte,
                    "end_byte": edit.end_byte,
                    "expected_text": edit.expected_text,
                    "replacement_text": edit.replacement_text,
                }
                for edit in request.edits
            ],
        }
    )


def _utf8_boundaries(text: str) -> frozenset[int]:
    offset = 0
    boundaries = {0}
    for character in text:
        offset += len(_strict_utf8(character, label="checkout source character"))
        boundaries.add(offset)
    return frozenset(boundaries)


def _affected_line_count(
    source: bytes,
    *,
    start: int,
    end: int,
    replacement: bytes,
) -> int:
    old_lines = 1 if start == end else source[start:end].count(b"\n") + 1
    replacement_lines = max(1, replacement.count(b"\n") + 1)
    return max(old_lines, replacement_lines)


def _within_prefix(logical_path: str, prefix: str) -> bool:
    return logical_path == prefix or logical_path.startswith(prefix + "/")


def _trusted_unified_diff(*, logical_path: str, before: str, after: str) -> str:
    return "".join(
        difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile=f"a/{logical_path}",
            tofile=f"b/{logical_path}",
            n=3,
            lineterm="\n",
        )
    )
