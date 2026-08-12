from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_GATE = _ROOT / "scripts" / "check_agent_memory_release.py"


def test_agent_memory_release_gate_has_packaging_and_isolated_smoke_boundaries() -> None:
    text = _GATE.read_text(encoding="utf-8")
    for phrase in (
        'glob("test_agent_memory*.py")',
        'glob("memory_*.py")',
        '"docs/releases/v0.30.0.md"',
        '"docs/rfcs/RFC-0030-secure-agent-memory-and-context-retrieval.md"',
        '"docs/migrations/v0.29.0-to-v0.30.0-agent-memory.md"',
        '"docs/security/RFC-0030-agent-memory-threat-model-review.md"',
        '"--no-deps"',
        '"--no-index"',
        '"-I"',
        "memory_scope_resource",
        "memory_record_resource",
        "DeterministicLexicalMemoryRetrievalAdapter",
        "InMemoryAgentMemoryStore",
    ):
        assert phrase in text


def test_agent_memory_release_gate_rejects_unsafe_archive_content() -> None:
    text = _GATE.read_text(encoding="utf-8")
    assert "_FORBIDDEN_ARCHIVE_COMPONENTS" in text
    assert "_FORBIDDEN_ARCHIVE_SUFFIXES" in text
    assert "member.issym() or member.islnk()" in text
