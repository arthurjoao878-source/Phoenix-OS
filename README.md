# Phoenix OS

Phoenix OS is an experimental, headless orchestration foundation for Python 3.12+.
Version `0.11.0` implements eleven accepted specifications:

- **RFC-0001 — Phoenix Kernel:** asynchronous request lifecycle, routing, authorization,
  confirmation, cancellation, deadlines, safe errors, and lifecycle events.
- **RFC-0002 — Event Bus:** immutable events, deterministic asynchronous delivery, priorities,
  one-shot and wildcard subscriptions, failure isolation, and explicit shutdown.
- **RFC-0003 — Capability Registry:** immutable capability contracts, trusted contexts,
  permissions, confirmation, deadlines, safe provider execution, discovery, and Kernel adapters.
- **RFC-0004 — Phoenix Runtime:** deterministic component startup, rollback, request draining,
  reverse shutdown, lifecycle states, deadlines, and context management.
- **RFC-0005 — Configuration System:** typed immutable configuration, ordered sources, provenance,
  explicit secrets, dependency composition, and Runtime assembly.
- **RFC-0006 — Observability and Diagnostics:** structured logs and metrics, asynchronous spans,
  deterministic sinks, recursive redaction, Event Bus observation, and Runtime ownership.
- **RFC-0007 — State Store and Persistence:** typed namespaced keys, safe JSON serialization,
  optimistic versions, TTL, serializable transactions, snapshots, and named-store lifecycle.
- **RFC-0008 — Plugin System and Adapter SDK:** immutable manifests, semantic compatibility,
  dependency ordering, least-authority exports, allowlisted discovery, rollback, and Runtime lifecycle.
- **RFC-0009 — Policy Engine and Security Context:** immutable identities, declarative rules,
  default-deny decisions, confirmation, explanations, and subsystem enforcement adapters.
- **RFC-0010 — Identity, Authentication and Sessions:** redacted credentials, trusted provider
  adapters, opaque bearer sessions, hashed persistence, expiry, revocation, and context propagation.
- **RFC-0011 — Secrets Vault and Key Management:** versioned secret references, authenticated
  policy enforcement, bounded leases, rotation, revocation, and external cryptographic boundaries.

The core intentionally contains no AI model, durable database driver, semantic-memory engine,
concrete tool, concrete identity provider, password database, cloud vault, cryptographic key provider, telemetry vendor, UI, or operating-system automation. Durable
storage belongs behind the State Store protocol; other integrations belong behind capability
providers, lifecycle components, named services, sinks, allowlisted plugins, and external adapters.
The plugin system is an authority boundary for SDK contributions, not a sandbox for hostile code.

## Install for development

```bash
python -m pip install -e ".[dev]"
```

## Validate

```bash
ruff check .
ruff format --check .
mypy
pytest
```

On Windows:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\check.ps1
```


## Secrets example

```python
from phoenix_os import KeyRef, SecretRef, SecretsManager, SecretValue

manager = SecretsManager(policy=policy)
ref = SecretRef("database-password", "production")
await manager.create(
    ref,
    SecretValue(password),
    security_context,
    protection_key=KeyRef("primary", "external-kms", 1),
)
lease = await manager.lease(ref, security_context)
```

Configuration should contain `SecretRef` values rather than raw credentials. The reference in-memory
store is not encrypted at rest; production encryption and key custody belong to reviewed external
`SecretStore` and `SecretProtector` adapters.

## Identity example

```python
from phoenix_os import (
    AuthenticationCredential,
    AuthenticationManager,
    CallableAuthenticationProvider,
    Identity,
    SecretValue,
)

provider = CallableAuthenticationProvider(authenticate_nova_user)
identity = AuthenticationManager((("nova", provider),))
grant = await identity.authenticate(
    "nova",
    AuthenticationCredential("password", SecretValue(password)),
)
session = await identity.resolve(grant.token)
```

Only a one-way digest is retained by the session repository. Password hashing, OAuth, LDAP, OIDC,
and external token verification belong inside trusted provider adapters.

## Policy example

```python
from phoenix_os import PolicyEffect, PolicyEngine, PolicyRequest, PolicyRule

policy = PolicyEngine((
    PolicyRule(
        "allow-profile",
        PolicyEffect.ALLOW,
        actions=frozenset({"state.read"}),
        resources=frozenset({"state:profile:*"}),
    ),
))
decision = await policy.evaluate(
    PolicyRequest("state.read", "state:profile:arthur"),
)
```

The engine is deny-by-default. Capability, State Store, Plugin, and Runtime adapters keep policy
centralized without coupling the Kernel to the authorization implementation.

## Plugin example

```python
from phoenix_os import HookPlugin, PluginManifest

plugin = HookPlugin(
    PluginManifest("nova.voice", "Nova Voice Adapter", "1.0.0"),
)
```

Plugins are loaded explicitly, validated before setup, and owned by `PluginManager`. See
`examples/plugin_system.py` for capability and service exports.

## State example

```python
from phoenix_os import ABSENT_VERSION, MemoryStateStore, StateKey

store = MemoryStateStore()
profile = StateKey("profile", "arthur", dict)
record = await store.put(
    profile,
    {"level": 1},
    expected_version=ABSENT_VERSION,
)
updated = await store.put(
    profile,
    {"level": 2},
    expected_version=record.version,
)
```

See `examples/` and `docs/` for complete contracts, configuration, dependency composition, Runtime
integration, authentication providers, sessions, secret references, leases, key providers, policy rules, security contexts, plugin manifests, dependency resolution, state
transactions, snapshots, trace context, redaction, and architectural decisions.

## License

MIT — Copyright (c) 2026 Phoenix contributors.
