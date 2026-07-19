# Migrating from Phoenix OS v0.20.0 to v0.21.0

Phoenix OS v0.21.0 keeps local operator identities and durable credentials compatible while changing
the administrative session transport and lifecycle.

## Runtime configuration

Existing `control_plane_operator_token`, registry, State Store, and operator-role configuration remain
valid. When a default State Store is available, `RuntimeAssembler` now creates a
`StateControlPlaneDurableSessionRepository`; otherwise it creates the bounded in-memory reference
repository. Optional constructor settings control session policy, repository capacity, cookie policy,
recovery polling, retention, and step-up windows.

No data migration is required for RFC-0020 operator records. RFC-0021 session records use their own
namespace and begin empty on first v0.21.0 start.

## HTTP clients

After `POST /v1/control-plane/operator/login`, do not look for `session_token` in JSON. Instead:

1. retain and return the host-only `Set-Cookie` value;
2. retain the `X-Phoenix-CSRF` response value;
3. send the cookie on protected requests;
4. send `X-Phoenix-CSRF` on state-changing requests;
5. replace both values whenever a protected response supplies rotated values.

The Dashboard performs this automatically and never exposes the session bearer to JavaScript.

Sensitive operator mutations require a recent proof from
`POST /v1/control-plane/operator/step-up`. Send the durable credential in `Authorization`, the
current session cookie and CSRF evidence, and the exact action. Pass the returned proof in
`X-Phoenix-Step-Up` on the matching mutation.

## Session lifecycle

Sessions now survive Runtime reconstruction when backed by State Store. They expire by absolute and
idle deadlines, rotate periodically without extending the original lifetime, and are invalidated by
operator status, access, or durable credential changes. Operators may inspect session history and
Maintainers may terminate one session or all active sessions for an operator.

Legacy `AdminTokenAuthenticator` mode remains supported and mutually exclusive with operator mode.
