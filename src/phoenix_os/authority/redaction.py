"""Safe non-authoritative diagnostic projections for RFC-0033."""

from __future__ import annotations

import hashlib
from datetime import datetime

from phoenix_os.authority.catalog import AuthorityCatalog
from phoenix_os.authority.contracts import (
    AuthorityExplanationResult,
    AuthorityInspectionResult,
    AuthorityInspectionState,
    AuthorityObservationProjection,
    AuthorityPathObservation,
    AuthoritySubject,
    AuthoritySubjectProjection,
)


def project_subject(subject: AuthoritySubject) -> AuthoritySubjectProjection:
    """Project a trusted subject without exposing a bearer session identity."""

    if not isinstance(subject, AuthoritySubject):
        raise TypeError("subject must be AuthoritySubject")
    session_identity: str | None = None
    if subject.session_id is not None:
        digest = hashlib.sha256(subject.session_id.bytes).hexdigest()
        session_identity = f"sha256:{digest}"
    return AuthoritySubjectProjection(
        principal_type=subject.principal_type,
        principal=subject.principal,
        session_identity=session_identity,
        agent_id=subject.agent_id,
        run_id=subject.run_id,
    )


def project_canonical_resource(
    observation: AuthorityPathObservation,
    catalog: AuthorityCatalog,
) -> str:
    """Project only resources matching the reviewed grammar for their exact action."""

    if not isinstance(observation, AuthorityPathObservation):
        raise TypeError("observation must be AuthorityPathObservation")
    if not isinstance(catalog, AuthorityCatalog):
        raise TypeError("catalog must be AuthorityCatalog")
    entry = catalog.validate_intent(observation.intent)
    resource = observation.intent.canonical_resource
    if observation.intent.action != "tool.invoke":
        return resource

    # Resolved tool resources are trusted for authorization but can contain subsystem
    # structure that is unnecessary for diagnostics. Preserve only the reviewed tool id.
    prefix = "tool:"
    if not resource.startswith(prefix) or "/" not in resource:
        raise ValueError("tool invocation resource is not structurally safe to project")
    tool_id, resolved = resource[len(prefix) :].split("/", 1)
    if not tool_id or not resolved:
        raise ValueError("tool invocation resource is not structurally safe to project")
    digest = hashlib.sha256(resolved.encode("utf-8")).hexdigest()
    projected = f"tool:{tool_id}/resource:sha256:{digest}"
    if not entry.accepts_resource(projected):
        raise ValueError("projected tool resource left the reviewed resource grammar")
    return projected


def project_observation(
    observation: AuthorityPathObservation,
    catalog: AuthorityCatalog,
) -> AuthorityObservationProjection:
    """Return the bounded safe projection of one validated observation."""

    if not isinstance(catalog, AuthorityCatalog):
        raise TypeError("catalog must be AuthorityCatalog")
    catalog.validate_observation(observation)
    return AuthorityObservationProjection(
        effect=observation.effect,
        requested_action=observation.intent.action,
        canonical_resource=project_canonical_resource(observation, catalog),
        authority_path=observation.boundaries,
        applicable_constraints=observation.constraints,
        denial_reason=observation.denial_reason,
        blocked_downstream_alternatives=observation.blocked_downstream,
    )


def project_inspection(
    state: AuthorityInspectionState,
    catalog: AuthorityCatalog,
) -> AuthorityInspectionResult:
    """Project an authorized inspection without promoting observation to authority."""

    if not isinstance(state, AuthorityInspectionState):
        raise TypeError("state must be AuthorityInspectionState")
    if not isinstance(catalog, AuthorityCatalog):
        raise TypeError("catalog must be AuthorityCatalog")
    return AuthorityInspectionResult(
        subject=project_subject(state.subject),
        observations=tuple(project_observation(item, catalog) for item in state.observations),
        observed_at=state.observed_at,
    )


def project_explanation(
    subject: AuthoritySubject,
    observation: AuthorityPathObservation,
    observed_at: datetime,
    catalog: AuthorityCatalog,
) -> AuthorityExplanationResult:
    """Project an authorized explanation using only safe typed fields."""

    if not isinstance(subject, AuthoritySubject):
        raise TypeError("subject must be AuthoritySubject")
    if not isinstance(catalog, AuthorityCatalog):
        raise TypeError("catalog must be AuthorityCatalog")
    return AuthorityExplanationResult(
        subject=project_subject(subject),
        observation=project_observation(observation, catalog),
        observed_at=observed_at,
    )
