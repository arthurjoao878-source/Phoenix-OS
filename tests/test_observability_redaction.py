from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

from phoenix_os import RedactionPolicy, SecretValue


def test_redaction_hides_sensitive_keys_recursively() -> None:
    policy = RedactionPolicy()
    result = policy.redact(
        {
            "username": "nova",
            "password": "unsafe",
            "nested": {
                "api-token": "unsafe-too",
                "safe": 7,
            },
        }
    )

    assert result["username"] == "nova"
    assert result["password"] == "***"
    nested = result["nested"]
    assert nested["api-token"] == "***"  # type: ignore[index]
    assert nested["safe"] == 7  # type: ignore[index]


def test_redaction_hides_secret_value_without_revealing_it() -> None:
    policy = RedactionPolicy()
    result = policy.redact({"value": SecretValue("do-not-leak")})
    assert result == {"value": "***"}


def test_redaction_converts_portable_types_and_unknown_objects() -> None:
    class Custom:
        pass

    now = datetime.now(UTC)
    identifier = uuid4()
    result = RedactionPolicy().redact(
        {
            "timestamp": now,
            "identifier": identifier,
            "path": Path("data/file.txt"),
            "custom": Custom(),
            "items": [1, "two"],
        }
    )

    assert result["timestamp"] == str(now)
    assert result["identifier"] == str(identifier)
    assert result["path"] == str(Path("data/file.txt"))
    assert result["custom"] == "<Custom>"
    assert result["items"] == (1, "two")


def test_redaction_limits_recursion_depth() -> None:
    result = RedactionPolicy(max_depth=2).redact({"a": {"b": {"c": 1}}})
    assert result["a"] == {"b": "<max-depth>"}


def test_redaction_policy_validates_configuration() -> None:
    with pytest.raises(ValueError, match="replacement"):
        RedactionPolicy(replacement="")
    with pytest.raises(ValueError, match="max_depth"):
        RedactionPolicy(max_depth=0)
    with pytest.raises(ValueError, match="sensitive keys"):
        RedactionPolicy(sensitive_keys=frozenset({" "}))


def test_redaction_rejects_blank_attribute_keys() -> None:
    with pytest.raises(ValueError, match="attribute keys"):
        RedactionPolicy().redact({" ": 1})
