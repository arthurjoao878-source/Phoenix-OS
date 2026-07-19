# Phoenix OS v0.20.0 — Local Operator Identity and Role-Based Access Control

Phoenix OS 0.20.0 implements RFC-0020 and replaces anonymous single-administrator operation with
identified local operators, deterministic roles, temporary sessions, durable credential digests, and
bounded Dashboard management.

## Highlights

- Viewer, Operator, and Maintainer roles with exact deterministic permissions;
- immutable operator records and bounded in-memory registry;
- State Store-backed registry with atomic username and credential-digest indexes;
- canonical JSON checksums and strict corruption detection;
- constant-time long-lived bearer authentication with generic external failures;
- credential rotation, disablement, reactivation, and terminal revocation;
- temporary process-local sessions with expiry and administrative revocation;
- bounded login throttling without authorization-header retention;
- authenticated operator management HTTP routes with origin-bound CSRF protection;
- one-time credential return for creation and rotation;
- operator-filtered command history and request-local journal attribution;
- Dashboard operator table, lifecycle controls, credential rotation, and history filter;
- RuntimeAssembler automatic State Store/in-memory registry selection and bootstrap maintainer;
- accepted RFC-0020 and ADR-0040/0041.

## Safety model

Plaintext long-lived credentials and temporary session tokens are never persisted, logged, emitted,
or included in exceptions. Persistent records contain SHA-256 digests only. Login failures do not
reveal whether an operator exists or is disabled. Operator responses use allowlisted serializers and
never include token digests. Lifecycle mutations use optimistic revisions, and revocation is terminal.

## Compatibility

`AdminTokenAuthenticator` remains available for transitional local integrations. New deployments
should configure `control_plane_operator_token` on `RuntimeAssembler`; the Runtime then owns a durable
operator registry when a default State Store exists. The bootstrap token is used only to create the
initial maintainer and does not silently replace an existing persisted credential.

## Validation

- Ruff lint and formatting passed;
- mypy strict passed;
- complete regression suite passed;
- wheel and source distribution passed Twine validation;
- Dashboard and operator modules are packaged in the wheel;
- package version reports 0.20.0.
