from __future__ import annotations

from pathlib import Path

_RFC = (
    Path(__file__).resolve().parents[1]
    / "docs"
    / "rfcs"
    / "RFC-0031-secure-agent-workspaces-and-artifact-handling.md"
)


def _text() -> str:
    return " ".join(_RFC.read_text(encoding="utf-8").split())


def test_rfc_0031_exists_as_v0310_draft() -> None:
    text = _text()
    assert "# RFC-0031: Secure Agent Workspaces and Artifact Handling" in text
    assert "- Status: Draft" in text
    assert "- Target release: Phoenix OS v0.31.0" in text
    assert "Files carry data, never authority." in text


def test_rfc_0031_defines_disabled_by_default_compatibility() -> None:
    text = _text()
    assert "The subsystem is disabled by default." in text
    assert "preserves v0.30.0 behavior" in text
    assert "workspace configuration is omitted" in text
    assert "Existing Phoenix OS v0.30.0" in text


def test_rfc_0031_defines_exact_workspace_actions() -> None:
    text = _text()
    for action in (
        "workspace.list",
        "workspace.read",
        "workspace.write",
        "workspace.delete",
        "workspace.import",
        "workspace.export",
        "workspace.admin",
    ):
        assert action in text


def test_rfc_0031_defines_exact_resource_shapes() -> None:
    text = _text()
    assert "agent-workspace:<namespace>/scope:<scope-kind>:<scope-id>" in text
    assert (
        "agent-workspace:<namespace>/scope:<scope-kind>:<scope-id>/artifact:<artifact-id>" in text
    )


def test_rfc_0031_keeps_workspace_authority_independent() -> None:
    text = _text()
    for authority in (
        "agent.run",
        "model.infer",
        "tool.invoke",
        "agent.delegate",
        "agent.resume",
        "agent.reconcile",
        "memory.*",
    ):
        assert authority in text
    assert "A workspace never grants generic host-filesystem authority." in text
    assert "Files carry data, never authority." in text


def test_rfc_0031_defines_server_owned_scope_and_paths() -> None:
    text = _text()
    for scope in ("run", "agent", "principal"):
        assert scope in text
    for phrase in (
        "never arbitrary model text",
        "cannot choose an arbitrary host filesystem path",
        "Canonical Phoenix-owned logical paths",
        "portable relative identifiers, not native filesystem paths",
        "drive/UNC/device forms",
        "special files",
        "link escapes",
    ):
        assert phrase in text


def test_rfc_0031_rejects_implicit_host_and_execution_authority() -> None:
    text = _text()
    for phrase in (
        "General-purpose unrestricted host filesystem access",
        "A shell, command runner, process launcher, or executable sandbox",
        "Implicit execution of scripts, binaries, documents, macros, installers, or archives",
        "Automatically mounting a user's home directory, Downloads, Desktop, or project tree",
        "Generic browser, desktop, shell, network, host-filesystem, or OS authority",
    ):
        assert phrase in text


def test_rfc_0031_defines_link_and_special_file_fail_closed_rules() -> None:
    text = _text()
    for phrase in (
        "Symlinks, hardlinks, reparse points, FIFOs, sockets, device nodes",
        "escapes the configured workspace root",
        "Artifact IDs are never reused",
        "A successful write never exposes a partially written authoritative artifact.",
        "Failed or cancelled writes do not become visible",
    ):
        assert phrase in text


def test_rfc_0031_defines_bounded_atomic_store_semantics() -> None:
    text = _text()
    for phrase in (
        "Artifact content has a strict configured byte bound.",
        "finite configured artifact-count and total-byte limits",
        "Quota admission and artifact mutation are atomic",
        "explicit version and canonical content digest",
        "optimistic version checks",
        "finite, and bounded by configuration",
    ):
        assert phrase in text


def test_rfc_0031_defines_explicit_transfer_boundaries() -> None:
    text = _text()
    for phrase in (
        "Import is an explicit server-mediated transfer",
        "Export is an explicit server-mediated transfer",
        "Import and export authority are independent",
        "The Phoenix core performs no implicit remote network fetch",
        "provider-neutral bounded results",
    ):
        assert phrase in text


def test_rfc_0031_defines_untrusted_agent_context() -> None:
    text = _text()
    for phrase in (
        "ArtifactContextBlock",
        "untrusted artifact data",
        "Binary artifacts are never silently decoded",
        "Text decoding failures fail closed",
        "Stored prompt injection cannot alter current authorization",
        "cannot become a system/policy message",
    ):
        assert phrase in text


def test_rfc_0031_defines_content_free_operations_and_safe_recovery() -> None:
    text = _text()
    for phrase in (
        "fail closed",
        "Recovery never resurrects deleted, expired",
        "content-free workspace metadata only",
        "Public failures expose no artifact bytes",
        "Runtime owns backing-store lifecycle",
    ):
        assert phrase in text


def test_rfc_0031_has_seventy_one_security_invariants() -> None:
    lines = _RFC.read_text(encoding="utf-8").splitlines()
    numbered = [line for line in lines if line[:1].isdigit() and ". " in line]
    invariants = []
    for line in numbered:
        prefix, _, _ = line.partition(". ")
        if prefix.isdigit():
            value = int(prefix)
            if 1 <= value <= 71:
                invariants.append(value)
    assert invariants == list(range(1, 72))


def test_rfc_0031_proposes_provider_neutral_contracts() -> None:
    text = _text()
    for contract in (
        "WorkspaceId",
        "ArtifactId",
        "ArtifactLogicalPath",
        "ArtifactVersion",
        "ArtifactDigest",
        "ArtifactProvenance",
        "WorkspaceLimits",
        "WorkspaceStore",
        "WorkspaceBackingAdapter",
        "WorkspaceTransferAdapter",
        "AgentWorkspaceService",
        "AgentWorkspaceRuntime",
        "AgentWorkspaceAdministration",
    ):
        assert f"`{contract}`" in text
    assert "provider-neutral" in text
    assert "open file handle" in text
    assert "process handle" in text


def test_rfc_0031_slices_zero_through_three_complete_and_later_slices_pending() -> None:
    text = _text()
    for slice_number in range(6):
        assert f"### Slice {slice_number} -" in text

    for item in (
        "Draft RFC-0031 with explicit security invariants",
        "Define exact workspace action/resource naming",
        "Define logical-path and host-confinement principles",
        "Define explicit import/export and untrusted-context boundaries",
        "Establish compatibility-by-omission contract",
        "Add RFC structure and regression tests",
    ):
        assert f"- [x] {item}" in text

    for item in (
        (
            "Immutable workspace/artifact identifiers, versions, digests, "
            "provenance, retention, and limits"
        ),
        "Canonical bounded Phoenix logical paths",
        "Exact `workspace.*` constants and resources",
        "Server-owned run, agent, and principal scope derivation",
        "Independent current-policy authorization",
        "Deterministic contract/path/authorization tests",
    ):
        assert f"- [x] {item}" in text
    for item in (
        "Reference authoritative workspace store",
        "Bounded artifact bytes, metadata, counts, and total quota",
        "Atomic writes and optimistic write/delete versions",
        "Retention, expiry, deletion, and ID anti-reuse behavior",
        "Provider-neutral backing adapter plus confined local reference adapter",
        "Persistence, path-escape, quota-race, and recovery tests",
        "Explicit bounded import contract and service path",
        "Explicit bounded export contract and service path",
        "Independent source/destination transfer authorization",
        "Provenance-preserving untrusted `ArtifactContextBlock`",
        "Agent-loop opt-in artifact context integration without authority promotion",
        "Injection, binary-decoding, cross-scope, and transfer regressions",
    ):
        assert f"- [x] {item}" in text

    assert "- [ ] Fail-closed startup/recovery" in text
    assert "- [ ] Threat-model/security-invariant review" in text
    assert "- [ ] Tag, artifacts, and checksums" in text


def test_rfc_0031_acceptance_keeps_host_authority_outside_workspace() -> None:
    text = _text()
    for phrase in (
        "arbitrary host paths cannot become agent authority",
        "fresh exact authorization",
        "mutations are atomic and quota-safe",
        "imports and exports are explicit independently authorized transfers",
        "artifact context remains untrusted",
        "preserves Phoenix OS v0.30.0 behavior",
    ):
        assert phrase in text
