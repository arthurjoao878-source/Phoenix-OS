# Migrating from Phoenix OS v0.22.0 to v0.23.0

Phoenix OS v0.23.0 adds optional durable service accounts and scoped API tokens
for machine clients. Existing operator sessions, remote-control policy, TLS,
cookies, CSRF, and step-up behavior remain unchanged when service accounts are
not enabled.

## Existing installations

No existing v0.22.0 operator or durable-session record is rewritten. Service
accounts and API tokens use their own repository records and begin empty.

Omitting the service-account composition settings preserves the v0.22.0
control-plane behavior. The upgrade does not create machine identities, issue
tokens, widen the network listener, or enable new machine routes implicitly.

## Enabling service accounts

1. Use durable operator mode and sign in as a Maintainer.
2. Provide a default State Store when service accounts must survive restart.
3. Configure only the exact machine routes required by the integration.
4. Create one service account per independent machine client or trust domain.
5. Issue a token with the smallest required scopes and resources.
6. Set a reviewed mandatory expiration.
7. Add client CIDR or mutual-TLS certificate restrictions where available.
8. Capture the displayed token immediately and store it in the client's secret
   manager.
9. Test authentication, authorization, expiry, replay rejection, rotation, and
   revocation before production use.

When no default State Store is available, RuntimeAssembler uses the bounded
in-memory reference repository. Its service accounts and tokens do not survive
process termination.

## Machine HTTP clients

API tokens are accepted only on explicitly allowlisted paths below
`/v1/control-plane/machine/`. They are not valid Dashboard credentials.

Each request must include:

- `Authorization: Bearer <token>`;
- `X-Phoenix-Request-Nonce` with a fresh request nonce;
- `X-Phoenix-Request-Timestamp` with a current timezone-aware timestamp.

`X-Phoenix-Correlation-Id` is optional. Machine requests do not send Dashboard
session cookies, CSRF values, operator credentials, or step-up proofs.

A retry must use a new nonce and timestamp. The token's exact scope and resource
grants must match the selected route, and central policy must also permit the
operation.

## Token custody

A newly issued or rotated token is displayed once. Phoenix OS persists only its
protected digest and safe metadata. There is no recovery endpoint for lost
plaintext.

Do not copy operator credentials into machine configuration. Do not store API
tokens in source control, logs, command history, URLs, metrics, audit payloads,
or State Store documents controlled by the integration.

## Rotation and revocation

Rotation creates a new token and can retain the predecessor only for an
explicit bounded overlap. Use zero overlap when the client can switch
atomically.

After deploying the successor, verify it independently and revoke any remaining
predecessor. Disabling a service account blocks its tokens without deleting
history. Revoking an account or token is terminal.

## Compatibility checklist

- Existing Dashboard login continues to use durable operator sessions.
- Browser mutations continue to require cookies, CSRF, exact Origin, and
  step-up where applicable.
- Existing loopback or remote network policy remains unchanged.
- API tokens never inherit Viewer, Operator, or Maintainer roles.
- No API token is accepted outside the explicit machine route allowlist.
- No plaintext token migration is required or supported.
