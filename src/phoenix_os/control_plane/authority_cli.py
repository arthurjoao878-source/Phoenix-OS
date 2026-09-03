"""Thin RFC-0033 authority diagnostics CLI over the durable control-plane HTTP boundary."""

from __future__ import annotations

import argparse
import getpass
import http.client
import ipaddress
import json
import re
import ssl
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import NoReturn
from urllib.parse import SplitResult, urlsplit

from phoenix_os.authority.contracts import (
    AuthorityConstraint,
    AuthorityDenialReason,
    AuthorityEffect,
    AuthorityExplanationResult,
    AuthorityInspectionResult,
    AuthorityObservationProjection,
    AuthoritySubjectProjection,
)
from phoenix_os.control_plane.operator_contracts import ControlPlaneOperatorToken
from phoenix_os.policy import PrincipalType

_LOGIN_PATH = "/v1/control-plane/operator/login"
_LOGOUT_PATH = "/v1/control-plane/operator/logout"
_INSPECT_PATH = "/v1/control-plane/authority/inspect"
_EXPLAIN_PATH = "/v1/control-plane/authority/explain"
_MAX_RESPONSE_BYTES = 1_048_576
_HTTP_TIMEOUT_SECONDS = 10.0
_COOKIE_NAME_PATTERN = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+\Z")
_DNS_NAME_PATTERN = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
)

type HeaderMap = Mapping[str, tuple[str, ...]]
type TokenReader = Callable[[str], str]


class _AuthorityCliError(RuntimeError):
    """Content-free CLI failure safe to display."""


class _AuthorityCliTransportError(_AuthorityCliError):
    """Network or protocol failure without secret-bearing details."""


class _AuthorityCliRejectedError(_AuthorityCliError):
    """Server-side authentication or authority rejection."""


@dataclass(frozen=True, slots=True)
class _Endpoint:
    scheme: str
    host: str
    port: int
    origin: str

    def connection(self) -> http.client.HTTPConnection:
        if self.scheme == "https":
            return http.client.HTTPSConnection(
                self.host,
                self.port,
                timeout=_HTTP_TIMEOUT_SECONDS,
                context=ssl.create_default_context(),
            )
        return http.client.HTTPConnection(
            self.host,
            self.port,
            timeout=_HTTP_TIMEOUT_SECONDS,
        )


@dataclass(frozen=True, slots=True)
class _HttpResult:
    status: int
    headers: dict[str, tuple[str, ...]]
    document: Mapping[str, object]


@dataclass(slots=True)
class _EphemeralSession:
    cookie: str
    csrf: str


type Sender = Callable[
    [_Endpoint, str, str, Mapping[str, str], bytes],
    _HttpResult,
]


class ControlPlaneAuthorityCliClient:
    """One-shot durable operator client for safe authority diagnostics."""

    def __init__(self, server: str, *, sender: Sender | None = None) -> None:
        self._endpoint = _parse_endpoint(server)
        self._sender: Sender = _send_http if sender is None else sender

    def inspect(self, target_ref: str, token: str) -> Mapping[str, object]:
        return self._one_shot(
            path=_INSPECT_PATH,
            body={"target_ref": target_ref},
            token=token,
            response_kind="inspect",
        )

    def explain(
        self,
        target_ref: str,
        action: str,
        token: str,
        *,
        resource_ref: str | None = None,
    ) -> Mapping[str, object]:
        body: dict[str, object] = {
            "target_ref": target_ref,
            "action": action,
        }
        if resource_ref is not None:
            body["resource_ref"] = resource_ref
        return self._one_shot(
            path=_EXPLAIN_PATH,
            body=body,
            token=token,
            response_kind="explain",
        )

    def _one_shot(
        self,
        *,
        path: str,
        body: Mapping[str, object],
        token: str,
        response_kind: str,
    ) -> Mapping[str, object]:
        credential = ControlPlaneOperatorToken(token)
        session = self._login(credential)
        try:
            response = self._post(
                path,
                session=session,
                document=body,
            )
            self._apply_rotation(session, response.headers)
            if response.status != 200:
                raise _rejection_for_status(response.status)
            _require_no_store(response.headers)
            return _validate_authority_document(response.document, response_kind)
        finally:
            primary_exception_active = sys.exc_info()[0] is not None
            try:
                self._logout(session)
            except _AuthorityCliError:
                if not primary_exception_active:
                    raise _AuthorityCliTransportError("session cleanup failed") from None

    def _login(self, token: ControlPlaneOperatorToken) -> _EphemeralSession:
        response = self._sender(
            self._endpoint,
            "POST",
            _LOGIN_PATH,
            {
                "Authorization": f"Bearer {token.value}",
                "Origin": self._endpoint.origin,
                "Accept": "application/json",
            },
            b"",
        )
        if response.status != 200:
            raise _AuthorityCliRejectedError("operator authentication rejected")
        cookie = _session_cookie(_one_header(response.headers, "set-cookie"))
        csrf = _safe_secret_header(_one_header(response.headers, "x-phoenix-csrf"))
        session = _EphemeralSession(cookie=cookie, csrf=csrf)
        try:
            _require_no_store(response.headers)
        except _AuthorityCliError:
            try:
                self._logout(session)
            except _AuthorityCliError:
                pass
            raise
        return session

    def _post(
        self,
        path: str,
        *,
        session: _EphemeralSession,
        document: Mapping[str, object] | None = None,
    ) -> _HttpResult:
        payload = b"" if document is None else _json_bytes(document)
        headers = {
            "Origin": self._endpoint.origin,
            "Cookie": session.cookie,
            "X-Phoenix-CSRF": session.csrf,
            "Accept": "application/json",
        }
        if document is not None:
            headers["Content-Type"] = "application/json"
        return self._sender(self._endpoint, "POST", path, headers, payload)

    def _logout(self, session: _EphemeralSession) -> None:
        response = self._post(_LOGOUT_PATH, session=session)
        if response.status == 200:
            _require_no_store_if_present(response.headers)
            return
        if response.status == 403:
            _require_no_store(response.headers)
            if self._apply_rotation(session, response.headers):
                response = self._post(_LOGOUT_PATH, session=session)
                if response.status == 200:
                    _require_no_store_if_present(response.headers)
                    return
        raise _AuthorityCliTransportError("session cleanup rejected")

    @staticmethod
    def _apply_rotation(session: _EphemeralSession, headers: HeaderMap) -> bool:
        set_cookie = _optional_one_header(headers, "set-cookie")
        csrf = _optional_one_header(headers, "x-phoenix-csrf")
        if set_cookie is None and csrf is None:
            return False
        if set_cookie is None or csrf is None:
            raise _AuthorityCliTransportError("incomplete session rotation")
        cookie = _session_cookie(set_cookie)
        csrf_token = _safe_secret_header(csrf)
        session.cookie = cookie
        session.csrf = csrf_token
        return True


def _send_http(
    endpoint: _Endpoint,
    method: str,
    path: str,
    headers: Mapping[str, str],
    body: bytes,
) -> _HttpResult:
    connection = endpoint.connection()
    try:
        connection.request(method, path, body=body, headers=dict(headers))
        response = connection.getresponse()
        raw = response.read(_MAX_RESPONSE_BYTES + 1)
        if len(raw) > _MAX_RESPONSE_BYTES:
            raise _AuthorityCliTransportError("control-plane response too large")
        header_map = _response_headers(response.getheaders())
        if not raw:
            document: Mapping[str, object] = {}
        else:
            decoded = json.loads(raw.decode("utf-8"))
            if not isinstance(decoded, dict):
                raise _AuthorityCliTransportError("invalid control-plane response")
            document = decoded
        return _HttpResult(
            status=response.status,
            headers=header_map,
            document=document,
        )
    except _AuthorityCliError:
        raise
    except (OSError, TimeoutError, http.client.HTTPException, UnicodeError, json.JSONDecodeError):
        raise _AuthorityCliTransportError("control-plane transport failed") from None
    finally:
        connection.close()


def _response_headers(items: Sequence[tuple[str, str]]) -> dict[str, tuple[str, ...]]:
    grouped: dict[str, list[str]] = {}
    for raw_name, raw_value in items:
        name = raw_name.strip().lower()
        value = raw_value.strip()
        if not name or "\r" in value or "\n" in value:
            raise _AuthorityCliTransportError("invalid control-plane response headers")
        grouped.setdefault(name, []).append(value)
    return {name: tuple(values) for name, values in grouped.items()}


def _parse_endpoint(value: str) -> _Endpoint:
    if not isinstance(value, str) or not value or len(value) > 2_048:
        raise ValueError("server must be a bounded control-plane origin")
    if any(character.isspace() for character in value):
        raise ValueError("server must not contain whitespace")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError("server must not contain control characters")
    if "?" in value or "#" in value:
        raise ValueError("server must not contain query or fragment")
    parts = urlsplit(value)
    _validate_origin_parts(parts)
    if parts.netloc.endswith(":"):
        raise ValueError("server origin contains an invalid port")
    host = parts.hostname
    if host is None or not host:
        raise ValueError("server origin requires a host")
    if not host.isascii() or "%" in host:
        raise ValueError("server host must be an ASCII hostname or IP literal")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        normalized_host = host.lower()
        if _DNS_NAME_PATTERN.fullmatch(normalized_host) is None:
            raise ValueError(
                "server host must be a canonical ASCII hostname or IP literal"
            ) from None
    else:
        normalized_host = address.compressed.lower()
    try:
        port = parts.port
    except ValueError as exception:
        raise ValueError("server origin contains an invalid port") from exception

    scheme = parts.scheme.lower()
    if scheme == "http":
        if port is None:
            raise ValueError("loopback HTTP server requires an explicit port")
        try:
            address = ipaddress.ip_address(host)
        except ValueError as exception:
            raise ValueError(
                "plaintext HTTP is allowed only for a loopback IP literal"
            ) from exception
        if not address.is_loopback:
            raise ValueError("plaintext HTTP is allowed only for loopback")
    elif scheme == "https":
        port = 443 if port is None else port
    else:
        raise ValueError("server origin must use http or https")

    assert port is not None
    if port <= 0:
        raise ValueError("server origin requires a nonzero port")
    rendered_host = f"[{normalized_host}]" if ":" in normalized_host else normalized_host
    default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    origin = f"{scheme}://{rendered_host}" + ("" if default_port else f":{port}")
    return _Endpoint(scheme=scheme, host=normalized_host, port=port, origin=origin)


def _validate_origin_parts(parts: SplitResult) -> None:
    if not parts.scheme or not parts.netloc:
        raise ValueError("server must be an absolute origin")
    if parts.username is not None or parts.password is not None:
        raise ValueError("server origin must not contain user information")
    if parts.path not in {"", "/"} or parts.query or parts.fragment:
        raise ValueError("server must contain only scheme, host, and port")


def _json_bytes(document: Mapping[str, object]) -> bytes:
    return json.dumps(
        document,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _one_header(headers: HeaderMap, name: str) -> str:
    values = headers.get(name, ())
    if len(values) != 1 or not values[0]:
        raise _AuthorityCliTransportError("required control-plane response header missing")
    return values[0]


def _optional_one_header(headers: HeaderMap, name: str) -> str | None:
    values = headers.get(name, ())
    if not values:
        return None
    if len(values) != 1 or not values[0]:
        raise _AuthorityCliTransportError("invalid control-plane response header")
    return values[0]


def _require_no_store(headers: HeaderMap) -> None:
    values = headers.get("cache-control", ())
    if len(values) != 1 or values[0].lower() != "no-store":
        raise _AuthorityCliTransportError("control-plane response is not non-cacheable")


def _require_no_store_if_present(headers: HeaderMap) -> None:
    values = headers.get("cache-control", ())
    if values and (len(values) != 1 or values[0].lower() != "no-store"):
        raise _AuthorityCliTransportError("control-plane response has unsafe cache policy")


def _session_cookie(set_cookie: str) -> str:
    pair = set_cookie.split(";", 1)[0]
    if "=" not in pair:
        raise _AuthorityCliTransportError("invalid session cookie")
    name, value = pair.split("=", 1)
    if _COOKIE_NAME_PATTERN.fullmatch(name) is None:
        raise _AuthorityCliTransportError("invalid session cookie")
    _safe_secret_header(value)
    return f"{name}={value}"


def _safe_secret_header(value: str) -> str:
    if not value or len(value) > 4_096:
        raise _AuthorityCliTransportError("invalid session material")
    try:
        value.encode("ascii")
    except UnicodeEncodeError:
        raise _AuthorityCliTransportError("invalid session material") from None
    if any(ord(character) < 33 or ord(character) == 127 for character in value):
        raise _AuthorityCliTransportError("invalid session material")
    if any(character in value for character in "\r\n;,"):
        raise _AuthorityCliTransportError("invalid session material")
    return value


def _rejection_for_status(status: int) -> _AuthorityCliRejectedError:
    if status == 401:
        return _AuthorityCliRejectedError("durable operator session rejected")
    if status == 403:
        return _AuthorityCliRejectedError("authority request rejected")
    if status == 400:
        return _AuthorityCliRejectedError("authority request invalid")
    return _AuthorityCliRejectedError("control-plane authority request failed")


def _validate_authority_document(
    document: Mapping[str, object],
    kind: str,
) -> Mapping[str, object]:
    if kind == "inspect":
        _require_exact_keys(
            document,
            {"schema_version", "subject", "observed_at", "observations"},
        )
        subject = _subject_projection(document["subject"])
        observed_at = _aware_datetime(document["observed_at"])
        observations_value = document["observations"]
        if not isinstance(observations_value, list):
            raise _AuthorityCliTransportError("invalid authority response schema")
        observations = tuple(_observation_projection(item) for item in observations_value)
        try:
            AuthorityInspectionResult(
                subject=subject,
                observations=observations,
                observed_at=observed_at,
            )
        except (TypeError, ValueError):
            raise _AuthorityCliTransportError("invalid authority response schema") from None
    elif kind == "explain":
        _require_exact_keys(
            document,
            {"schema_version", "subject", "observed_at", "observation"},
        )
        try:
            AuthorityExplanationResult(
                subject=_subject_projection(document["subject"]),
                observation=_observation_projection(document["observation"]),
                observed_at=_aware_datetime(document["observed_at"]),
            )
        except (TypeError, ValueError):
            raise _AuthorityCliTransportError("invalid authority response schema") from None
    else:
        raise _AuthorityCliTransportError("unsupported authority response kind")

    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise _AuthorityCliTransportError("unsupported authority response schema")
    return document


def _subject_projection(value: object) -> AuthoritySubjectProjection:
    document = _object(value)
    _require_exact_keys(
        document,
        {"principal_type", "principal", "session_identity", "agent_id", "run_id"},
    )
    try:
        projection = AuthoritySubjectProjection(
            principal_type=PrincipalType(_string(document["principal_type"])),
            principal=_string(document["principal"]),
            session_identity=_optional_string(document["session_identity"]),
            agent_id=_optional_string(document["agent_id"]),
            run_id=_optional_string(document["run_id"]),
        )
    except (TypeError, ValueError):
        raise _AuthorityCliTransportError("invalid authority subject projection") from None
    expected: Mapping[str, object] = {
        "principal_type": projection.principal_type.value,
        "principal": projection.principal,
        "session_identity": projection.session_identity,
        "agent_id": projection.agent_id,
        "run_id": projection.run_id,
    }
    if document != expected:
        raise _AuthorityCliTransportError("non-canonical authority subject projection")
    return projection


def _observation_projection(value: object) -> AuthorityObservationProjection:
    document = _object(value)
    _require_exact_keys(
        document,
        {
            "effect",
            "requested_action",
            "canonical_resource",
            "authority_path",
            "applicable_constraints",
            "denial_reason",
            "blocked_downstream_alternatives",
        },
    )
    try:
        projection = AuthorityObservationProjection(
            effect=AuthorityEffect(_string(document["effect"])),
            requested_action=_string(document["requested_action"]),
            canonical_resource=_string(document["canonical_resource"]),
            authority_path=_string_tuple(document["authority_path"]),
            applicable_constraints=tuple(
                AuthorityConstraint(item)
                for item in _string_tuple(document["applicable_constraints"])
            ),
            denial_reason=(
                None
                if document["denial_reason"] is None
                else AuthorityDenialReason(_string(document["denial_reason"]))
            ),
            blocked_downstream_alternatives=_string_tuple(
                document["blocked_downstream_alternatives"]
            ),
        )
    except (TypeError, ValueError):
        raise _AuthorityCliTransportError("invalid authority observation projection") from None
    expected: Mapping[str, object] = {
        "effect": projection.effect.value,
        "requested_action": projection.requested_action,
        "canonical_resource": projection.canonical_resource,
        "authority_path": list(projection.authority_path),
        "applicable_constraints": [item.value for item in projection.applicable_constraints],
        "denial_reason": (
            None if projection.denial_reason is None else projection.denial_reason.value
        ),
        "blocked_downstream_alternatives": list(projection.blocked_downstream_alternatives),
    }
    if document != expected:
        raise _AuthorityCliTransportError("non-canonical authority observation projection")
    return projection


def _object(value: object) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise _AuthorityCliTransportError("invalid authority response schema")
    return value


def _require_exact_keys(document: Mapping[str, object], keys: set[str]) -> None:
    if set(document) != keys:
        raise _AuthorityCliTransportError("invalid authority response schema")


def _string(value: object) -> str:
    if not isinstance(value, str):
        raise _AuthorityCliTransportError("invalid authority response schema")
    return value


def _optional_string(value: object) -> str | None:
    if value is None:
        return None
    return _string(value)


def _string_tuple(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise _AuthorityCliTransportError("invalid authority response schema")
    return tuple(_string(item) for item in value)


def _aware_datetime(value: object) -> datetime:
    text = _string(value)
    if len(text) > 64:
        raise _AuthorityCliTransportError("invalid authority observation time")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        raise _AuthorityCliTransportError("invalid authority observation time") from None
    if parsed.tzinfo is None or parsed.utcoffset() is None or parsed.isoformat() != text:
        raise _AuthorityCliTransportError("invalid authority observation time")
    return parsed


class _SafeArgumentParser(argparse.ArgumentParser):
    """Argparse variant that never echoes rejected user-supplied values."""

    def error(self, message: str) -> NoReturn:
        del message
        self.print_usage(sys.stderr)
        self.exit(2, "phoenix: invalid arguments\n")


def _parser() -> argparse.ArgumentParser:
    parser = _SafeArgumentParser(prog="phoenix")
    commands = parser.add_subparsers(dest="command", required=True)
    authority = commands.add_parser("authority", help="inspect point-in-time effective authority")
    authority.add_argument(
        "--server",
        required=True,
        help="control-plane origin; plaintext is accepted only for loopback",
    )
    authority_commands = authority.add_subparsers(dest="authority_command", required=True)

    inspect_parser = authority_commands.add_parser("inspect", help="inspect a trusted target")
    inspect_parser.add_argument("target_ref")

    explain_parser = authority_commands.add_parser("explain", help="explain one exact action")
    explain_parser.add_argument("target_ref")
    explain_parser.add_argument("action")
    explain_parser.add_argument("resource_ref", nargs="?")

    from phoenix_os.control_plane.operator_cli import add_operator_commands

    add_operator_commands(commands)
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    token_reader: TokenReader = getpass.getpass,
    sender: Sender | None = None,
) -> int:
    parser = _parser()
    arguments = parser.parse_args(argv)

    if arguments.command != "authority":
        from phoenix_os.control_plane.operator_cli import run_operator_command

        return run_operator_command(arguments)

    try:
        client = ControlPlaneAuthorityCliClient(arguments.server, sender=sender)
        token = token_reader("Operator token: ")
        if arguments.authority_command == "inspect":
            result = client.inspect(arguments.target_ref, token)
        elif arguments.authority_command == "explain":
            result = client.explain(
                arguments.target_ref,
                arguments.action,
                token,
                resource_ref=arguments.resource_ref,
            )
        else:
            _unreachable()
    except (EOFError, KeyboardInterrupt):
        print("phoenix: credential input cancelled", file=sys.stderr)
        return 3
    except ValueError:
        print("phoenix: invalid credential or server origin", file=sys.stderr)
        return 3
    except _AuthorityCliError as exception:
        print(f"phoenix: {exception}", file=sys.stderr)
        return 4

    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def _unreachable() -> NoReturn:
    raise RuntimeError("unreachable authority CLI command")
