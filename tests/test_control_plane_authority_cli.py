from __future__ import annotations

import json
import tomllib
from collections.abc import Mapping
from pathlib import Path

import pytest

from phoenix_os.control_plane import authority_cli as cli

TOKEN = "operator-token-0123456789abcdef0123456789"
OLD_COOKIE = "phoenix_session=session-old-0123456789abcdef"
OLD_CSRF = "csrf-old-0123456789abcdef0123456789"
NEW_COOKIE = "phoenix_session=session-new-0123456789abcdef"
NEW_CSRF = "csrf-new-0123456789abcdef0123456789"
ORIGIN = "http://127.0.0.1:8080"


def _subject() -> dict[str, object]:
    return {
        "principal_type": "user",
        "principal": "alice",
        "session_identity": "sha256:" + ("a" * 64),
        "agent_id": "agent-42",
        "run_id": "run-7",
    }


def _observation() -> dict[str, object]:
    return {
        "effect": "allowed",
        "requested_action": "host.app.launch",
        "canonical_resource": "host-automation:profile:vscode",
        "authority_path": ["tool.invoke", "host.app.launch"],
        "applicable_constraints": ["canonical_boundary", "policy"],
        "denial_reason": None,
        "blocked_downstream_alternatives": ["host.app.close"],
    }


def _inspection() -> dict[str, object]:
    return {
        "schema_version": 1,
        "subject": _subject(),
        "observed_at": "2026-08-22T22:00:00+00:00",
        "observations": [_observation()],
    }


def _explanation() -> dict[str, object]:
    return {
        "schema_version": 1,
        "subject": _subject(),
        "observed_at": "2026-08-22T22:00:00+00:00",
        "observation": _observation(),
    }


def _result(
    status: int,
    *,
    headers: Mapping[str, tuple[str, ...]] | None = None,
    document: Mapping[str, object] | None = None,
) -> cli._HttpResult:
    return cli._HttpResult(
        status=status,
        headers=dict(headers or {}),
        document={} if document is None else document,
    )


def _login_result() -> cli._HttpResult:
    return _result(
        200,
        headers={
            "cache-control": ("no-store",),
            "set-cookie": (OLD_COOKIE + "; Path=/; HttpOnly; SameSite=Strict",),
            "x-phoenix-csrf": (OLD_CSRF,),
        },
    )


class _ScriptedSender:
    def __init__(
        self,
        authority_result: cli._HttpResult,
        *,
        logout_result: cli._HttpResult | None = None,
    ) -> None:
        self.authority_result = authority_result
        self.logout_result = logout_result or _result(200)
        self.calls: list[tuple[cli._Endpoint, str, str, Mapping[str, str], bytes]] = []

    def __call__(
        self,
        endpoint: cli._Endpoint,
        method: str,
        path: str,
        headers: Mapping[str, str],
        body: bytes,
    ) -> cli._HttpResult:
        self.calls.append((endpoint, method, path, dict(headers), body))
        if path == "/v1/control-plane/operator/login":
            return _login_result()
        if path in {
            "/v1/control-plane/authority/inspect",
            "/v1/control-plane/authority/explain",
        }:
            return self.authority_result
        if path == "/v1/control-plane/operator/logout":
            return self.logout_result
        raise AssertionError(f"unexpected path: {path}")


def test_pyproject_registers_only_thin_phoenix_entry_point() -> None:
    document = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    project = document["project"]

    assert project["scripts"] == {"phoenix": "phoenix_os.control_plane.authority_cli:main"}
    assert project["dependencies"] == []


@pytest.mark.parametrize(
    ("server", "origin"),
    [
        ("http://127.0.0.1:8080", "http://127.0.0.1:8080"),
        ("http://127.0.0.1:80", "http://127.0.0.1"),
        ("http://[::1]:8080", "http://[::1]:8080"),
        ("http://[0:0:0:0:0:0:0:1]:8080", "http://[::1]:8080"),
        ("https://Admin.Example.com", "https://admin.example.com"),
        ("https://Admin.Example.com:443", "https://admin.example.com"),
        ("https://[0:0:0:0:0:0:0:1]", "https://[::1]"),
        ("https://admin.example.com:8443", "https://admin.example.com:8443"),
    ],
)
def test_server_origin_accepts_only_reviewed_transport_shapes(
    server: str,
    origin: str,
) -> None:
    client = cli.ControlPlaneAuthorityCliClient(server, sender=lambda *args: _result(500))

    assert client._endpoint.origin == origin


@pytest.mark.parametrize(
    "server",
    [
        "http://localhost:8080",
        "http://192.0.2.1:8080",
        "http://127.0.0.1",
        "http://127.0.0.1:0",
        "https://admin.example.com:0",
        "https://user@admin.example.com",
        "https://admin.example.com/path",
        "https://admin.example.com?query=1",
        "https://admin.example.com#fragment",
        "https://admin.example.com?",
        "https://admin.example.com#",
        "https://admin.example.com:",
        "https://[::1]:",
        "ftp://127.0.0.1:8080",
        "http://127.0.0.1:99999",
        " http://127.0.0.1:8080",
        "http://127.0.0.1:8080 ",
        "https://admin example.com",
        "https://admin.example.com :443",
        "https://bad_host.example",
        "https://admin.example.com.",
        "https://-bad.example",
        "https://bad-.example",
        "https://a..example",
        "http://127.0.0.1:8080\nignored",
    ],
)
def test_server_origin_rejects_plaintext_remote_and_non_origins(server: str) -> None:
    with pytest.raises(ValueError):
        cli.ControlPlaneAuthorityCliClient(server, sender=lambda *args: _result(500))


def test_invalid_login_cache_policy_revokes_issued_ephemeral_session() -> None:
    calls: list[tuple[cli._Endpoint, str, str, Mapping[str, str], bytes]] = []

    def sender(
        endpoint: cli._Endpoint,
        method: str,
        path: str,
        headers: Mapping[str, str],
        body: bytes,
    ) -> cli._HttpResult:
        calls.append((endpoint, method, path, dict(headers), body))
        if path == "/v1/control-plane/operator/login":
            return _result(
                200,
                headers={
                    "set-cookie": (OLD_COOKIE + "; Path=/; HttpOnly; SameSite=Strict",),
                    "x-phoenix-csrf": (OLD_CSRF,),
                },
            )
        if path == "/v1/control-plane/operator/logout":
            return _result(200, headers={"cache-control": ("no-store",)})
        raise AssertionError(f"unexpected path: {path}")

    client = cli.ControlPlaneAuthorityCliClient(ORIGIN, sender=sender)

    with pytest.raises(cli._AuthorityCliTransportError, match="non-cacheable"):
        client.inspect("agent-42", TOKEN)

    assert [call[2] for call in calls] == [
        "/v1/control-plane/operator/login",
        "/v1/control-plane/operator/logout",
    ]
    assert calls[-1][3]["Cookie"] == OLD_COOKIE
    assert calls[-1][3]["X-Phoenix-CSRF"] == OLD_CSRF


def test_inspect_uses_bearer_only_for_login_and_rotated_session_for_logout() -> None:
    inspection = _inspection()
    sender = _ScriptedSender(
        _result(
            200,
            headers={
                "cache-control": ("no-store",),
                "set-cookie": (NEW_COOKIE + "; Path=/; HttpOnly; SameSite=Strict",),
                "x-phoenix-csrf": (NEW_CSRF,),
            },
            document=inspection,
        )
    )
    client = cli.ControlPlaneAuthorityCliClient(ORIGIN, sender=sender)

    result = client.inspect("agent-42", TOKEN)

    assert result == inspection
    assert [call[2] for call in sender.calls] == [
        "/v1/control-plane/operator/login",
        "/v1/control-plane/authority/inspect",
        "/v1/control-plane/operator/logout",
    ]

    _, method, _, login_headers, login_body = sender.calls[0]
    assert method == "POST"
    assert login_body == b""
    assert login_headers["Authorization"] == f"Bearer {TOKEN}"
    assert login_headers["Origin"] == ORIGIN
    assert "Cookie" not in login_headers
    assert "X-Phoenix-CSRF" not in login_headers

    _, _, _, inspect_headers, inspect_body = sender.calls[1]
    assert "Authorization" not in inspect_headers
    assert inspect_headers["Origin"] == ORIGIN
    assert inspect_headers["Cookie"] == OLD_COOKIE
    assert inspect_headers["X-Phoenix-CSRF"] == OLD_CSRF
    assert json.loads(inspect_body) == {"target_ref": "agent-42"}

    _, _, _, logout_headers, logout_body = sender.calls[2]
    assert logout_body == b""
    assert "Authorization" not in logout_headers
    assert logout_headers["Origin"] == ORIGIN
    assert logout_headers["Cookie"] == NEW_COOKIE
    assert logout_headers["X-Phoenix-CSRF"] == NEW_CSRF


def test_explain_sends_only_server_resolved_selector_fields() -> None:
    explanation = _explanation()
    sender = _ScriptedSender(
        _result(
            200,
            headers={"cache-control": ("no-store",)},
            document=explanation,
        )
    )
    client = cli.ControlPlaneAuthorityCliClient(ORIGIN, sender=sender)

    result = client.explain(
        "agent-42",
        "host.app.launch",
        TOKEN,
        resource_ref="vscode",
    )

    assert result == explanation
    _, _, path, headers, body = sender.calls[1]
    assert path == "/v1/control-plane/authority/explain"
    assert "Authorization" not in headers
    assert json.loads(body) == {
        "action": "host.app.launch",
        "resource_ref": "vscode",
        "target_ref": "agent-42",
    }


def test_response_with_extra_identity_field_fails_closed_and_is_not_returned() -> None:
    inspection = _inspection()
    inspection["subject"] = {
        **_subject(),
        "session_id": "00000000-0000-0000-0000-000000000999",
    }
    sender = _ScriptedSender(
        _result(
            200,
            headers={"cache-control": ("no-store",)},
            document=inspection,
        )
    )
    client = cli.ControlPlaneAuthorityCliClient(ORIGIN, sender=sender)

    with pytest.raises(cli._AuthorityCliTransportError, match="schema"):
        client.inspect("agent-42", TOKEN)

    assert sender.calls[-1][2] == "/v1/control-plane/operator/logout"


@pytest.mark.parametrize(
    "mutation",
    ["schema_type", "action_case", "constraints_order", "timestamp", "missing_no_store"],
)
def test_noncanonical_or_cacheable_authority_response_fails_closed(mutation: str) -> None:
    inspection = _inspection()
    headers: dict[str, tuple[str, ...]] = {"cache-control": ("no-store",)}
    if mutation == "schema_type":
        inspection["schema_version"] = 1.0
    elif mutation == "action_case":
        observation = _observation()
        observation["requested_action"] = "HOST.APP.LAUNCH"
        inspection["observations"] = [observation]
    elif mutation == "constraints_order":
        observation = _observation()
        observation["applicable_constraints"] = ["policy", "canonical_boundary"]
        inspection["observations"] = [observation]
    elif mutation == "timestamp":
        inspection["observed_at"] = "2026-08-22 22:00:00+00:00"
    else:
        headers = {}
    sender = _ScriptedSender(_result(200, headers=headers, document=inspection))
    client = cli.ControlPlaneAuthorityCliClient(ORIGIN, sender=sender)

    with pytest.raises(cli._AuthorityCliTransportError):
        client.inspect("agent-42", TOKEN)

    assert sender.calls[-1][2] == "/v1/control-plane/operator/logout"


def test_oversized_inspection_fails_closed_and_still_logs_out() -> None:
    inspection = _inspection()
    inspection["observations"] = [_observation() for _ in range(257)]
    sender = _ScriptedSender(
        _result(
            200,
            headers={"cache-control": ("no-store",)},
            document=inspection,
        )
    )
    client = cli.ControlPlaneAuthorityCliClient(ORIGIN, sender=sender)

    with pytest.raises(cli._AuthorityCliTransportError, match="schema"):
        client.inspect("agent-42", TOKEN)

    assert sender.calls[-1][2] == "/v1/control-plane/operator/logout"


def test_unexpected_validation_failure_still_attempts_logout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sender = _ScriptedSender(
        _result(
            200,
            headers={"cache-control": ("no-store",)},
            document=_inspection(),
        )
    )
    client = cli.ControlPlaneAuthorityCliClient(ORIGIN, sender=sender)

    def fail_validation(document: Mapping[str, object], kind: str) -> Mapping[str, object]:
        del document, kind
        raise RuntimeError("validation sentinel")

    monkeypatch.setattr(cli, "_validate_authority_document", fail_validation)

    with pytest.raises(RuntimeError, match="validation sentinel"):
        client.inspect("agent-42", TOKEN)

    assert sender.calls[-1][2] == "/v1/control-plane/operator/logout"


def test_invalid_paired_rotation_does_not_partially_replace_session() -> None:
    sender = _ScriptedSender(
        _result(
            200,
            headers={
                "cache-control": ("no-store",),
                "set-cookie": (NEW_COOKIE + "; Path=/; HttpOnly",),
                "x-phoenix-csrf": ("invalid csrf token",),
            },
            document=_inspection(),
        )
    )
    client = cli.ControlPlaneAuthorityCliClient(ORIGIN, sender=sender)

    with pytest.raises(cli._AuthorityCliTransportError, match="session material"):
        client.inspect("agent-42", TOKEN)

    logout_headers = sender.calls[-1][3]
    assert logout_headers["Cookie"] == OLD_COOKIE
    assert logout_headers["X-Phoenix-CSRF"] == OLD_CSRF


def test_partial_session_rotation_fails_closed_and_cleans_original_session() -> None:
    sender = _ScriptedSender(
        _result(
            200,
            headers={
                "cache-control": ("no-store",),
                "set-cookie": (NEW_COOKIE + "; Path=/; HttpOnly",),
            },
            document=_inspection(),
        )
    )
    client = cli.ControlPlaneAuthorityCliClient(ORIGIN, sender=sender)

    with pytest.raises(cli._AuthorityCliTransportError, match="rotation"):
        client.inspect("agent-42", TOKEN)

    logout_headers = sender.calls[-1][3]
    assert logout_headers["Cookie"] == OLD_COOKIE
    assert logout_headers["X-Phoenix-CSRF"] == OLD_CSRF


def test_logout_retries_once_with_server_rotated_session_material() -> None:
    inspection = _inspection()
    calls: list[tuple[cli._Endpoint, str, str, Mapping[str, str], bytes]] = []
    logout_calls = 0

    def sender(
        endpoint: cli._Endpoint,
        method: str,
        path: str,
        headers: Mapping[str, str],
        body: bytes,
    ) -> cli._HttpResult:
        nonlocal logout_calls
        calls.append((endpoint, method, path, dict(headers), body))
        if path == "/v1/control-plane/operator/login":
            return _login_result()
        if path == "/v1/control-plane/authority/inspect":
            return _result(
                200,
                headers={"cache-control": ("no-store",)},
                document=inspection,
            )
        if path == "/v1/control-plane/operator/logout":
            logout_calls += 1
            if logout_calls == 1:
                return _result(
                    403,
                    headers={
                        "cache-control": ("no-store",),
                        "set-cookie": (NEW_COOKIE + "; Path=/; HttpOnly",),
                        "x-phoenix-csrf": (NEW_CSRF,),
                    },
                    document={"error": "request_rejected"},
                )
            return _result(200, headers={"cache-control": ("no-store",)})
        raise AssertionError(f"unexpected path: {path}")

    client = cli.ControlPlaneAuthorityCliClient(ORIGIN, sender=sender)

    assert client.inspect("agent-42", TOKEN) == inspection
    logout_requests = [call for call in calls if call[2] == "/v1/control-plane/operator/logout"]
    assert len(logout_requests) == 2
    assert logout_requests[0][3]["Cookie"] == OLD_COOKIE
    assert logout_requests[0][3]["X-Phoenix-CSRF"] == OLD_CSRF
    assert logout_requests[1][3]["Cookie"] == NEW_COOKIE
    assert logout_requests[1][3]["X-Phoenix-CSRF"] == NEW_CSRF


def test_cleanup_failure_suppresses_otherwise_valid_observation() -> None:
    sender = _ScriptedSender(
        _result(
            200,
            headers={"cache-control": ("no-store",)},
            document=_inspection(),
        ),
        logout_result=_result(403, document={"error": "request_rejected"}),
    )
    client = cli.ControlPlaneAuthorityCliClient(ORIGIN, sender=sender)

    with pytest.raises(cli._AuthorityCliTransportError, match="cleanup"):
        client.inspect("agent-42", TOKEN)


def test_primary_rejection_wins_over_cleanup_failure() -> None:
    sender = _ScriptedSender(
        _result(
            403,
            headers={"cache-control": ("no-store",)},
            document={"error": "forbidden"},
        ),
        logout_result=_result(403, document={"error": "request_rejected"}),
    )
    client = cli.ControlPlaneAuthorityCliClient(ORIGIN, sender=sender)

    with pytest.raises(cli._AuthorityCliRejectedError, match="rejected"):
        client.inspect("agent-42", TOKEN)

    assert sender.calls[-1][2] == "/v1/control-plane/operator/logout"


def test_server_rejection_document_is_never_echoed_by_main(
    capsys: pytest.CaptureFixture[str],
) -> None:
    secret = "server-secret-that-must-not-be-echoed"
    sender = _ScriptedSender(
        _result(
            403,
            headers={"cache-control": ("no-store",)},
            document={"error": "forbidden", "internal": secret},
        )
    )

    exit_code = cli.main(
        ["authority", "--server", ORIGIN, "inspect", "agent-42"],
        token_reader=lambda prompt: TOKEN,
        sender=sender,
    )

    captured = capsys.readouterr()
    assert exit_code == 4
    assert captured.out == ""
    assert secret not in captured.err
    assert TOKEN not in captured.err


def test_cli_never_accepts_or_echoes_bearer_on_command_line(
    capsys: pytest.CaptureFixture[str],
) -> None:
    accidental_secret = "secret-on-command-line-0123456789abcdef"

    with pytest.raises(SystemExit) as captured_exit:
        cli.main(
            [
                "authority",
                "--server",
                ORIGIN,
                "inspect",
                "agent-42",
                "--token",
                accidental_secret,
            ],
            token_reader=lambda prompt: TOKEN,
        )

    captured = capsys.readouterr()
    assert captured_exit.value.code == 2
    assert accidental_secret not in captured.err
    assert accidental_secret not in captured.out


def test_invalid_interactive_credential_is_not_echoed(
    capsys: pytest.CaptureFixture[str],
) -> None:
    invalid_secret = "x" * 31

    exit_code = cli.main(
        ["authority", "--server", ORIGIN, "inspect", "agent-42"],
        token_reader=lambda prompt: invalid_secret,
        sender=lambda *args: pytest.fail("invalid token must fail before transport"),
    )

    captured = capsys.readouterr()
    assert exit_code == 3
    assert captured.out == ""
    assert invalid_secret not in captured.err


def test_successful_main_prints_only_validated_redacted_projection(
    capsys: pytest.CaptureFixture[str],
) -> None:
    inspection = _inspection()
    sender = _ScriptedSender(
        _result(
            200,
            headers={"cache-control": ("no-store",)},
            document=inspection,
        )
    )

    exit_code = cli.main(
        ["authority", "--server", ORIGIN, "inspect", "agent-42"],
        token_reader=lambda prompt: TOKEN,
        sender=sender,
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert json.loads(captured.out) == inspection
    assert TOKEN not in captured.out
    assert OLD_COOKIE not in captured.out
    assert OLD_CSRF not in captured.out
    assert captured.err == ""


def test_cli_module_does_not_import_or_invoke_authorizer_layers() -> None:
    assert cli.__file__ is not None
    source = Path(cli.__file__).read_text(encoding="utf-8")

    assert "AuthorityService" not in source
    assert "PolicyEngine" not in source
    assert "authority_integration" not in source
    assert "from phoenix_os.authority import" not in source
    assert "/v1/control-plane/authority/inspect" in source
    assert "/v1/control-plane/authority/explain" in source
