"""Server-owned provenance propagation and cross-subsystem data-flow admission for RFC-0036."""

from __future__ import annotations

import json
from collections.abc import Mapping
from types import MappingProxyType

from phoenix_os.integrated_agent.contracts import (
    IntegratedDataFlowDecision,
    IntegratedDataFlowDisposition,
    IntegratedDataFlowPolicy,
    IntegratedDataFlowRoute,
    IntegratedDataProvenance,
    IntegratedDataProvenanceAtom,
    IntegratedDataSink,
    IntegratedDataSourceKind,
    IntegratedResultAudience,
)
from phoenix_os.integrated_agent.errors import (
    IntegratedAgentDataFlowDeniedError,
    IntegratedAgentProvenanceOverflowError,
    IntegratedAgentValidationError,
)
from phoenix_os.policy import SecurityContext


def integrated_provenance_union(
    *values: IntegratedDataProvenance,
    derived_atom: IntegratedDataProvenanceAtom | None = None,
) -> IntegratedDataProvenance:
    """Return the exact conservative provenance union without declassification or truncation."""

    atoms: list[IntegratedDataProvenanceAtom] = []
    for value in values:
        if not isinstance(value, IntegratedDataProvenance):
            raise TypeError("values must contain IntegratedDataProvenance values")
        atoms.extend(value.atoms)
    if derived_atom is not None:
        if not isinstance(derived_atom, IntegratedDataProvenanceAtom):
            raise TypeError("derived_atom must be IntegratedDataProvenanceAtom or None")
        atoms.append(derived_atom)
    if not atoms:
        raise ValueError("integrated provenance union requires at least one source atom")
    try:
        return IntegratedDataProvenance(tuple(atoms))
    except ValueError as exception:
        if "PROVENANCE_OVERFLOW" in str(exception):
            raise IntegratedAgentProvenanceOverflowError() from exception
        raise


_PERSISTED_PROVENANCE_ATTRIBUTE_PREFIX = "rfc0036.provenance."
_PERSISTED_PROVENANCE_CHUNK_CHARS = 1_024
_PERSISTED_PROVENANCE_MAX_CHUNKS = 31
MAX_PERSISTED_INTEGRATED_PROVENANCE_BYTES = (
    _PERSISTED_PROVENANCE_CHUNK_CHARS * _PERSISTED_PROVENANCE_MAX_CHUNKS
)


def integrated_provenance_to_persistence_attributes(
    provenance: IntegratedDataProvenance,
) -> Mapping[str, str]:
    """Encode exact integrated lineage into bounded opaque storage attributes."""

    if not isinstance(provenance, IntegratedDataProvenance):
        raise TypeError("provenance must be IntegratedDataProvenance")
    payload = _persisted_provenance_bytes(provenance)
    if len(payload) > MAX_PERSISTED_INTEGRATED_PROVENANCE_BYTES:
        raise IntegratedAgentProvenanceOverflowError()

    encoded = payload.decode("ascii")
    chunks = tuple(
        encoded[offset : offset + _PERSISTED_PROVENANCE_CHUNK_CHARS]
        for offset in range(
            0,
            len(encoded),
            _PERSISTED_PROVENANCE_CHUNK_CHARS,
        )
    )
    if not chunks or len(chunks) > _PERSISTED_PROVENANCE_MAX_CHUNKS:
        raise IntegratedAgentProvenanceOverflowError()
    return MappingProxyType(
        {
            f"{_PERSISTED_PROVENANCE_ATTRIBUTE_PREFIX}{index:02d}": chunk
            for index, chunk in enumerate(chunks)
        }
    )


def integrated_provenance_from_persistence_attributes(
    attributes: Mapping[str, str],
) -> IntegratedDataProvenance | None:
    """Decode exact integrated lineage; malformed envelopes fail closed."""

    if not isinstance(attributes, Mapping):
        raise TypeError("attributes must be a mapping")
    if any(
        not isinstance(key, str) or not isinstance(value, str) for key, value in attributes.items()
    ):
        raise IntegratedAgentValidationError("persisted provenance attributes are invalid")

    keys = tuple(
        key for key in attributes if key.startswith(_PERSISTED_PROVENANCE_ATTRIBUTE_PREFIX)
    )
    if not keys:
        return None

    indexed: dict[int, str] = {}
    for key in keys:
        suffix = key[len(_PERSISTED_PROVENANCE_ATTRIBUTE_PREFIX) :]
        if len(suffix) != 2 or not suffix.isdigit():
            raise IntegratedAgentValidationError("persisted provenance chunk key is invalid")
        index = int(suffix)
        if index >= _PERSISTED_PROVENANCE_MAX_CHUNKS or index in indexed:
            raise IntegratedAgentValidationError("persisted provenance chunk index is invalid")
        value = attributes[key]
        if not value or len(value) > _PERSISTED_PROVENANCE_CHUNK_CHARS:
            raise IntegratedAgentValidationError("persisted provenance chunk is invalid")
        indexed[index] = value

    if set(indexed) != set(range(len(indexed))):
        raise IntegratedAgentValidationError("persisted provenance chunks are not contiguous")

    payload_text = "".join(indexed[index] for index in range(len(indexed)))
    try:
        payload = payload_text.encode("ascii")
    except UnicodeEncodeError as exception:
        raise IntegratedAgentValidationError(
            "persisted provenance is not canonical ASCII"
        ) from exception
    if len(payload) > MAX_PERSISTED_INTEGRATED_PROVENANCE_BYTES:
        raise IntegratedAgentProvenanceOverflowError()

    try:
        decoded: object = json.loads(payload_text)
    except (json.JSONDecodeError, RecursionError) as exception:
        raise IntegratedAgentValidationError("persisted provenance JSON is invalid") from exception
    if not isinstance(decoded, list) or not decoded:
        raise IntegratedAgentValidationError("persisted provenance requires source atoms")

    atoms: list[IntegratedDataProvenanceAtom] = []
    try:
        for raw in decoded:
            if not isinstance(raw, dict) or set(raw) != {
                "source_kind",
                "source_binding",
                "freshness_bindings",
            }:
                raise IntegratedAgentValidationError("persisted provenance atom is invalid")
            source_kind = raw["source_kind"]
            source_binding = raw["source_binding"]
            freshness = raw["freshness_bindings"]
            if (
                not isinstance(source_kind, str)
                or not isinstance(source_binding, str)
                or not isinstance(freshness, list)
                or any(not isinstance(item, str) for item in freshness)
            ):
                raise IntegratedAgentValidationError("persisted provenance atom is invalid")
            atoms.append(
                IntegratedDataProvenanceAtom(
                    source_kind=IntegratedDataSourceKind(source_kind),
                    source_binding=source_binding,
                    freshness_bindings=tuple(freshness),
                )
            )
        provenance = IntegratedDataProvenance(tuple(atoms))
    except IntegratedAgentValidationError:
        raise
    except (TypeError, ValueError) as exception:
        if "PROVENANCE_OVERFLOW" in str(exception):
            raise IntegratedAgentProvenanceOverflowError() from exception
        raise IntegratedAgentValidationError("persisted provenance is invalid") from exception

    if _persisted_provenance_bytes(provenance) != payload:
        raise IntegratedAgentValidationError("persisted provenance is not canonical")
    return provenance


def _persisted_provenance_bytes(
    provenance: IntegratedDataProvenance,
) -> bytes:
    return json.dumps(
        [
            {
                "freshness_bindings": list(atom.freshness_bindings),
                "source_binding": atom.source_binding,
                "source_kind": atom.source_kind.value,
            }
            for atom in provenance.atoms
        ],
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def integrated_result_audience(context: SecurityContext) -> IntegratedResultAudience:
    """Derive the only USER_RESULT audience from trusted authenticated Phoenix context."""

    if not isinstance(context, SecurityContext):
        raise TypeError("context must be SecurityContext")
    if not context.authenticated:
        raise IntegratedAgentDataFlowDeniedError()
    return IntegratedResultAudience(
        principal=context.principal,
        session_id=context.session_id,
    )


class IntegratedDataFlowGuard:
    """Evaluate exact provenance atoms against one immutable server-owned route policy."""

    def __init__(self, policy: IntegratedDataFlowPolicy) -> None:
        if not isinstance(policy, IntegratedDataFlowPolicy):
            raise TypeError("policy must be IntegratedDataFlowPolicy")
        self._policy = policy

    @property
    def policy(self) -> IntegratedDataFlowPolicy:
        return self._policy

    def decide(
        self,
        provenance: IntegratedDataProvenance,
        sink: IntegratedDataSink,
        *,
        context: SecurityContext | None = None,
    ) -> tuple[IntegratedDataFlowDecision, ...]:
        """Return one deterministic content-free decision per exact provenance atom."""

        if not isinstance(provenance, IntegratedDataProvenance):
            raise TypeError("provenance must be IntegratedDataProvenance")
        if not isinstance(sink, IntegratedDataSink):
            raise TypeError("sink must be IntegratedDataSink")
        if context is not None and not isinstance(context, SecurityContext):
            raise TypeError("context must be SecurityContext or None")

        audience_available = False
        if sink is IntegratedDataSink.USER_RESULT:
            if context is None or not context.authenticated:
                return tuple(
                    IntegratedDataFlowDecision(
                        source_kind=atom.source_kind,
                        sink=sink,
                        disposition=IntegratedDataFlowDisposition.DENY,
                    )
                    for atom in provenance.atoms
                )
            integrated_result_audience(context)
            audience_available = True

        return tuple(
            self._decide_atom(
                atom,
                sink,
                audience_available=audience_available,
            )
            for atom in provenance.atoms
        )

    def admit(
        self,
        provenance: IntegratedDataProvenance,
        sink: IntegratedDataSink,
        *,
        context: SecurityContext | None = None,
    ) -> tuple[IntegratedDataFlowDecision, ...]:
        """Fail closed unless every exact provenance atom has one unambiguous ALLOW route."""

        decisions = self.decide(provenance, sink, context=context)
        if any(
            decision.disposition is not IntegratedDataFlowDisposition.ALLOW
            for decision in decisions
        ):
            raise IntegratedAgentDataFlowDeniedError()
        return decisions

    def _decide_atom(
        self,
        atom: IntegratedDataProvenanceAtom,
        sink: IntegratedDataSink,
        *,
        audience_available: bool,
    ) -> IntegratedDataFlowDecision:
        matches = tuple(
            route
            for route in self._policy.routes
            if _route_matches(
                route,
                atom,
                sink,
                audience_available=audience_available,
            )
        )
        if len(matches) != 1:
            return IntegratedDataFlowDecision(
                source_kind=atom.source_kind,
                sink=sink,
                disposition=IntegratedDataFlowDisposition.DENY,
            )
        route = matches[0]
        return IntegratedDataFlowDecision(
            source_kind=atom.source_kind,
            sink=sink,
            disposition=route.disposition,
            route_id=route.route_id,
        )


def _route_matches(
    route: IntegratedDataFlowRoute,
    atom: IntegratedDataProvenanceAtom,
    sink: IntegratedDataSink,
    *,
    audience_available: bool,
) -> bool:
    if route.source_kind is not atom.source_kind or route.sink is not sink:
        return False
    if route.source_scope is not None and not _binding_within_scope(
        atom.source_binding,
        route.source_scope,
    ):
        return False
    if not set(route.required_freshness_bindings).issubset(atom.freshness_bindings):
        return False
    if route.requires_audience_match and not audience_available:
        return False
    return True


def _binding_within_scope(source_binding: str, source_scope: str) -> bool:
    return source_binding == source_scope or source_binding.startswith(f"{source_scope}/")
