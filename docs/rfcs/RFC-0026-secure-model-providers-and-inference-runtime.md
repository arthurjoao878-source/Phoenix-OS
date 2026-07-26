# RFC-0026: Secure Model Providers and Inference Runtime

- Status: Draft
- Target release: Phoenix OS v0.26.0
- Owners: Phoenix OS maintainers
- Depends on: RFC-0002, RFC-0004, RFC-0005, RFC-0006, RFC-0009, RFC-0011, RFC-0012, and RFC-0024

## Summary

RFC-0026 defines an optional provider-neutral inference boundary for Phoenix OS.

The subsystem lets trusted Phoenix components request bounded text-model inference
through explicitly registered providers and models. It standardizes complete and
streamed responses, cancellation, deadlines, usage metadata, policy evaluation,
secret leasing, safe network configuration, audit, observability, and Runtime
lifecycle ownership.

Inference is disabled by default. No provider, model, endpoint, credential,
network permission, request, or background worker exists unless explicitly
configured. Model output is always untrusted data and never becomes authority to
invoke capabilities, commands, jobs, workflows, plugins, or operating-system
automation.

## Motivation

Phoenix OS currently has secure Runtime, configuration, policy, secrets, audit,
persistence, service-account, webhook, and inbound-event boundaries, but it does
not define how an AI model is selected or invoked.

Embedding provider SDK calls directly into applications would couple credentials,
network destinations, request formats, retries, streaming behavior, usage
accounting, logs, and failures to individual features. It would also make it easy
for model output to cross into privileged execution without an explicit policy
boundary.

A dedicated inference subsystem must isolate provider-specific transport from
Phoenix-owned contracts and preserve least authority before later RFCs add agent
loops, tool calling, local automation, memory, or voice.

## Goals

- Optional inference disabled by default
- Provider-neutral immutable request, response, chunk, usage, and error contracts
- Explicit provider and model registration with stable identifiers
- Exact provider and model allowlisting
- Exact policy action and concrete resource authorization
- Versioned Secrets Vault references leased only during provider execution
- Explicit hosted or loopback-local endpoint policy
- HTTPS verification for hosted providers
- SSRF-resistant destination validation and redirect control
- Bounded input messages, output bytes, tokens, chunks, duration, and concurrency
- Complete and streaming inference modes
- Cooperative cancellation and finite deadlines
- Stable request identifiers for tracing and audit
- Deterministic fake provider for tests without network or paid usage
- Safe provider-error normalization
- Safe usage and finish-reason reporting
- Content-free audit and observability by default
- RuntimeAssembler lifecycle ownership
- Compatibility with Phoenix OS v0.25.0 deployments

## Non-goals

- Agent planning or autonomous loops
- Tool or capability calling
- Executing model-produced commands
- Operating-system automation
- Persistent conversation or semantic memory
- Retrieval-augmented generation
- Training, fine-tuning, embeddings, image, audio, or video generation
- Provider account creation or credential provisioning
- Automatic model discovery from remote endpoints
- Caller-selected arbitrary provider URLs
- Automatic failover between providers
- Transparent retries that may duplicate billable inference
- Guaranteed deterministic provider output
- Treating model output as trusted instructions, policy, identity, or code
- Persisting prompts or responses by default
- A hostile-code sandbox for provider adapters

## Threat model

The subsystem treats prompts, system instructions, conversation messages,
provider responses, streamed chunks, usage reports, finish reasons, provider
metadata, endpoint responses, and model-generated structured data as untrusted.

The implementation must address credential leakage, endpoint substitution, SSRF,
redirect abuse, TLS downgrade, model confusion, unauthorized model use, prompt
or response disclosure, cross-request contamination, unbounded token or byte
consumption, concurrency exhaustion, slow streams, cancellation races, partial
responses, duplicate billable requests, provider error leakage, malicious
adapter behavior, logging leaks, prompt injection, and model output attempting to
obtain capability or operating-system authority.

## Security invariants

1. Inference is disabled unless explicitly configured.
2. Enabling inference creates no provider, model, endpoint, credential, network authority, request, or worker automatically.
3. Every provider and model has a stable server-side identifier from trusted configuration.
4. Callers select only registered provider and model identifiers, never arbitrary endpoints or credentials.
5. Every request requires the exact `model.infer` action and a concrete provider-and-model resource.
6. Policy approval for inference never grants capability, command, job, workflow, plugin, or operating-system authority.
7. Model output is untrusted data and never executes directly.
8. Provider adapters receive only the bounded request fields and leased credentials required for one invocation.
9. Credentials use exact versioned `SecretRef` values and are leased only during provider execution.
10. Plaintext credentials never enter request, response, event, audit, metric, health, or persisted state.
11. Hosted endpoints require verified HTTPS and explicit destination policy.
12. Plain HTTP is permitted only for an explicitly configured loopback-local provider.
13. Redirects are disabled by default and cannot escape the reviewed destination policy.
14. Requests cannot supply proxy, DNS, TLS, certificate, Host, or redirect policy.
15. Input messages, strings, metadata, output bytes, token budgets, chunks, duration, queue depth, and concurrency are finite.
16. Streaming chunks are ordered, bounded, and associated with one stable request identifier.
17. A streamed request is successful only after one terminal finish record.
18. Cancellation and deadlines stop local consumption and bound provider cleanup.
19. The initial Runtime performs no transparent retry after provider execution begins.
20. Provider usage reports are bounded metadata and are not trusted for authorization.
21. Provider-specific failures map to safe Phoenix errors without response bodies, secrets, or internal exceptions.
22. Prompt and response content are excluded from audit, metrics, health, and logs by default.
23. Any optional content retention requires a later explicit reviewed contract and is outside this RFC.
24. Provider adapters are trusted installed code but receive no ambient Phoenix authority.
25. Existing v0.25.0 behavior remains unchanged when inference configuration is absent.

## Proposed contracts

- `ModelProviderId`
- `ModelId`
- `ModelDescriptor`
- `ModelCapabilities`
- `InferenceRole`
- `InferenceMessage`
- `InferenceRequest`
- `InferenceResponse`
- `InferenceChunk`
- `InferenceUsage`
- `InferenceFinishReason`
- `InferenceLimits`
- `ModelEndpointPolicy`
- `ModelCredentialPolicy`
- `ModelProvider`
- `ModelProviderRegistry`
- `InferenceAuthorizer`
- `InferenceRuntime`
- `InferenceSnapshot`
- `InferenceObserver`
- `InferenceError`

## Request and response model

An `InferenceRequest` contains a stable request identifier, registered provider
and model identifiers, ordered immutable messages, optional bounded generation
parameters, a finite deadline, a finite output budget, optional safe correlation
metadata, and the authenticated Phoenix security context used for policy
evaluation.

The request cannot contain an endpoint, API key, arbitrary transport headers,
proxy configuration, TLS settings, provider account identifier, executable
callback, capability, command, job, workflow, or plugin reference.

A complete `InferenceResponse` contains the stable request identifier, bounded
output text, terminal finish reason, safe usage metadata, provider and model
identifiers, and bounded timing metadata. It contains no credential, raw
transport response, internal exception, provider SDK object, or unrestricted
headers.

## Provider and model registry

Providers and models register before the Runtime accepts inference. A provider
registration declares a stable identifier, adapter type, endpoint policy,
credential policy, model allowlist, capability declarations, mandatory limits,
and lifecycle state.

A model descriptor declares a stable model identifier, supported inference
modes, input and output limits, optional provider-specific aliases held inside
trusted configuration, and compatibility metadata. Callers cannot discover or
select unregistered remote models.

Duplicate providers, duplicate models, incompatible capabilities, missing
credential references, unsafe endpoint policies, and limits above global
ceilings fail closed during composition.

The Phoenix package includes a deterministic fake provider for tests and examples.
Hosted-provider and local-model adapters remain optional integrations behind the
same contracts.

## Authorization and authority separation

Every invocation requires central policy approval for the exact
`model.infer` action and a concrete resource in the form
`model-provider:<provider-id>/model:<model-id>`.

Authorization decides only whether the bounded inference request may be sent.
It does not authorize tools, capabilities, commands, jobs, workflows, plugins,
external events, webhooks, or operating-system actions.

Model output, including structured JSON or text that resembles a command, remains
untrusted input for later explicitly authorized subsystems. A future agent RFC
must perform a new independent policy decision before any privileged action.

## Credentials and endpoint security

Provider credentials are represented by exact versioned Secrets Vault references.
The inference Runtime leases only the required secret version immediately before
adapter execution, passes the minimum credential material to the adapter, clears
temporary mutable buffers where supported, and revokes the lease after completion,
failure, timeout, or cancellation.

Hosted providers require explicit HTTPS endpoint configuration, certificate
verification, bounded connection and read timeouts, and fail-closed destination
validation. Redirects are disabled by default. Requests cannot alter the scheme,
authority, port, path prefix, proxy, DNS behavior, certificate policy, or
credential destination.

Loopback-local providers may use explicit HTTP only when the endpoint resolves to
a reviewed loopback address and the configuration forbids proxy use and remote
redirection. Enabling a local adapter never binds a new Phoenix listener.

## Limits, budgets, and admission

Global, provider, model, and request limits are finite. The most restrictive
applicable limit wins.

Limits cover message count, message bytes, individual string length, metadata
width, input estimate, requested output tokens, response bytes, chunk count,
chunk bytes, queue depth, concurrent requests, connect timeout, first-byte
timeout, total duration, cancellation grace, and safe usage metadata.

Admission occurs before credential leasing or network activity. Saturated
requests fail with a safe bounded error. The initial design does not estimate or
enforce monetary cost because provider pricing is external and mutable; adapters
may report bounded usage facts for observation.

## Complete and streaming execution

`InferenceRuntime.infer` returns one complete response. `InferenceRuntime.stream`
returns ordered immutable chunks followed by exactly one terminal record.

The Runtime assigns and preserves the request identifier, applies limits while
reading, rejects malformed or out-of-order adapter output, and never exposes raw
provider streaming frames. Partial text may be delivered to the caller, but a
stream without a valid terminal record is failed or cancelled rather than
reported as complete.

Cancellation is cooperative and bounded. The Runtime stops accepting chunks,
signals the adapter, revokes credential leases after bounded cleanup, releases
admission capacity, and records only safe completion metadata.

## Retry, failure, and cancellation semantics

The initial Runtime performs no transparent retry after provider execution begins
because providers may charge or generate distinct output for repeated requests.

Connection setup failures that occur before any request body or credential-bearing
authorization is transmitted may be exposed as retryable safe errors, but caller
retry remains explicit. Adapters must report execution phase without leaking
provider internals.

Timeout, cancellation, malformed output, limit exhaustion, provider rejection,
transport failure, and internal adapter failure map to stable Phoenix error
categories. Raw response bodies, provider tracebacks, request content, secrets,
and unrestricted headers are never returned.

## Audit, observability, and events

Safe audit facts cover provider registration, model registration, lifecycle
changes, authorization decisions, invocation start, completion category,
cancellation, timeout, limit rejection, and configuration failure.

Audit, logs, metrics, health, and Event Bus observations contain only approved
metadata such as stable identifiers, bounded durations, finish category, token
counts when supplied, byte counts, queue state, and redacted correlation data.
Prompt text, response text, credentials, authorization headers, raw provider
errors, and model-generated structured payloads are excluded by default.

Any Event Bus event emitted by the subsystem uses a Phoenix-owned fixed event
type and content-free metadata. Model output never becomes an event payload
automatically.

## Configuration and RuntimeAssembler integration

Inference composition is optional. Configuration declares provider registrations,
model descriptors, endpoint and credential policies, global ceilings, admission
limits, timeouts, streaming limits, and whether the subsystem is enabled.

When enabled, `RuntimeAssembler` validates configuration, composes the provider
registry, resolves policy and Secrets Vault dependencies, creates the inference
Runtime and admission state, registers safe diagnostics, and starts no background
network listener.

Startup validates providers and models before exposing the service. Shutdown
rejects new requests, cancels or drains active invocations within finite bounds,
revokes remaining leases, closes adapters in reverse order, and removes the
service last. Partial startup rolls back deterministically.

## Compatibility and migration

Inference providers are optional and begin empty. With inference composition
omitted, Phoenix OS preserves all v0.25.0 Runtime, Control Plane, Dashboard,
inbound-event, webhook, service-account, session, jobs, workflows, audit, secrets,
Event Bus, network, TLS, and persistence behavior.

No provider, model, endpoint, secret reference, policy grant, request, output,
network permission, or persistent content is created during upgrade.

The package version remains `0.25.0` during implementation slices and changes to
`0.26.0` only in the final release slice. Migration must support disabled
configuration, fake-provider validation, reviewed provider and model registration,
credential setup, endpoint verification, conservative canary enablement,
observation, and rollback by disabling new inference while preserving unrelated
Phoenix state.

## Slice plan

### Slice 1 — Contracts, registry, and deterministic provider

- [x] Immutable inference request, response, chunk, usage, and error contracts
- [x] Strict provider, model, role, finish-reason, and limit validation
- [x] Provider and model registry with duplicate rejection
- [x] Deterministic fake provider with complete and streaming modes
- [x] Bounded request and response codecs
- [x] Provider capability compatibility checks
- [x] Contract, registry, and fake-provider tests

### Slice 2 — Authorization, secrets, and endpoint security

- [x] Exact `model.infer` action and concrete provider-model resources
- [x] Central policy integration and default-deny behavior
- [x] Exact versioned `SecretRef` credential leasing
- [x] Hosted HTTPS endpoint validation and redirect denial
- [x] Explicit loopback-local HTTP policy
- [x] SSRF, proxy, DNS, TLS, and credential-leakage tests
- [x] Generic authorization and provider-enumeration failures

### Slice 3 — Execution, streaming, cancellation, and limits

- [x] Complete inference execution
- [x] Ordered bounded streaming with one terminal record
- [x] Cooperative cancellation and finite cleanup
- [x] Deadline, first-byte, duration, byte, token, and chunk limits
- [x] Global, provider, and model admission controls
- [x] No-transparent-retry execution semantics
- [x] Timeout, malformed-stream, saturation, and race tests

### Slice 4 — Configuration, Runtime, audit, and observability

- [x] Typed provider, model, endpoint, credential, and limit configuration
- [x] RuntimeAssembler optional composition and deterministic rollback
- [x] Safe Runtime service exposure and health snapshots
- [x] Content-free audit facts and redacted observability
- [x] Phoenix-owned content-free Event Bus lifecycle events
- [x] Bounded shutdown, cancellation, and adapter cleanup
- [x] Compatibility tests with inference omitted

### Slice 5 — Administration and v0.26.0

- [ ] Maintainer-only provider and model administration
- [ ] Dashboard provider lifecycle and content-free invocation health
- [ ] Optional scoped service-account administration
- [ ] Migration guidance and rollback procedure
- [ ] Architecture Decision Records
- [ ] Security, limits, streaming, and packaging release gate
- [ ] Release notes, version 0.26.0, tag, artifacts, and checksums

The Slice 1 implementation adds the dependency-free `phoenix_os.inference`
package with immutable identifiers, messages, requests, responses, chunks,
usage, capabilities, limits, descriptors, safe error categories, a deterministic
provider/model registry, strict canonical schema-v1 transport codecs, and a
deterministic network-free provider for complete and streamed tests.

No hosted-provider SDK, credential, endpoint, network request, policy grant,
Runtime service, agent loop, tool call, persistence, or operating-system
automation is introduced by this slice. Provider responses are untrusted, and model output remains untrusted data
without implicit Phoenix authority.

The Slice 2 implementation adds exact `model.infer` authorization against
concrete provider-model resources through the central deny-by-default Policy
Engine. It adds exact versioned `SecretRef` leases that are revoked after adapter
use and generic public failures that do not enumerate providers, models, secrets,
or credential versions.

Hosted endpoints require canonical HTTPS and admitted public or explicitly
allowlisted networks. Explicit loopback-local development may use HTTP only when
every resolved address is loopback. DNS answers are fully admitted and returned
as pinned literal destination addresses; redirects and ambient proxies remain
disabled.

No provider HTTP request, hosted-provider SDK, TLS connector, credential header,
Runtime composition, or agent execution is introduced by this slice.

The Slice 3 implementation adds the asynchronous `InferenceRuntime` for
authorized complete and streaming execution. It performs request admission before
provider execution, applies fail-fast global, provider, and model admission,
enforces absolute deadlines, first-byte and total-duration timeouts, UTF-8 byte
budgets, model character and chunk ceilings, and requested output-token limits.

Provider streams are consumed as ordered immutable chunks and expose exactly one
validated terminal record. Missing, duplicate, extra, out-of-order, mismatched,
oversized, or over-budget output fails closed. Caller cancellation and early
consumer closure cancel pending provider work and attempt adapter cleanup within
a finite grace period.

No execution path performs a transparent retry after provider work begins. No
hosted-provider transport, provider SDK, network request, RuntimeAssembler
composition, persistence, agent loop, tool calling, or operating-system
automation is introduced by this slice.

The Slice 4 implementation adds immutable provider and subsystem
configuration for registered models, endpoint policy, exact credential policy,
execution limits, admission limits, and bounded shutdown. Optional
`RuntimeAssembler` composition validates installed providers exactly, exposes
`inference`, `inference.runtime`, `inference.registry`, and `inference.health`
services, and preserves existing Runtime behavior when inference is omitted.

The Runtime-owned inference service publishes only Phoenix-defined lifecycle and
invocation event types with empty payloads and approved content-free metadata.
Audit facts, logs, metrics, and health snapshots exclude prompt text, response
text, credentials, endpoint details, raw provider failures, and streaming frames.
Shutdown first drains active invocations, then cooperatively cancels remaining
work within finite bounds before closing the provider registry.

No hosted-provider SDK, HTTP client, DNS resolver, TLS connector, credential
header, prompt persistence, response persistence, agent loop, tool calling, or
operating-system automation is introduced by this slice.

## Acceptance

RFC-0026 may be accepted for Phoenix OS 0.26.0 only when every slice is complete,
the full quality gate passes, package artifacts install in isolated offline
environments, provider credentials and request content remain excluded from safe
output, endpoint policy fails closed, cancellation and limits are bounded, model
output receives no implicit authority, and compatibility without configured
inference is demonstrated.
