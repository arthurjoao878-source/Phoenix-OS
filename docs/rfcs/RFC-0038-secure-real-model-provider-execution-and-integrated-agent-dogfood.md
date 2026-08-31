# RFC-0038: Secure Real-Model Provider Execution and Integrated Agent Dogfood

- Status: Draft
- Target release: Phoenix OS v0.38.0
- Owners: Phoenix OS maintainers
- Architecture freeze: pending dogfood-planning review
- Depends on: RFC-0004, RFC-0005, RFC-0006, RFC-0008, RFC-0009, RFC-0011,
  RFC-0012, RFC-0021, RFC-0026, RFC-0027, RFC-0028, RFC-0030, RFC-0031,
  RFC-0032, RFC-0033, RFC-0034, RFC-0035, RFC-0036, and RFC-0037

## Summary

RFC-0038 moves Phoenix OS from predominantly deterministic model/test adapters to
reviewed real-model execution and serious integrated dogfood.

The release does not redefine Phoenix as a coding assistant, bind Phoenix to one
model family, create a second inference subsystem, or weaken the authority model
developed through RFC-0037.

Instead, it closes the remaining production seam between RFC-0026 model inference
and RFC-0027 agent model turns, introduces a reviewed first local provider
integration, and exercises existing Phoenix capabilities in real end-to-end tasks.

The first reference deployment is:

```text
Phoenix OS
  -> RFC-0026 inference boundary
  -> reviewed Ollama local provider
  -> explicitly configured local model
```

The initial dogfood model may be Qwen3-Coder 30B-A3B through Ollama, but the model is
deployment configuration rather than Phoenix identity or architecture.

The dominant rules are:

> **A real model gains no authority that a deterministic model did not have.**

> **Provider-specific transport is an adapter concern; authorization, identity,
> limits, recovery, and tool authority remain Phoenix concerns.**

> **A model existing at a provider does not make that model configured or
> authorized in Phoenix.**

> **Real-provider dogfood must exercise Phoenix as a general agent runtime, not
> optimize the core around one coding workflow.**

> **Dogfood evidence may discover future work, but it does not justify bypassing
> existing security boundaries.**

## Motivation

Phoenix OS v0.37.0 has the major architecture required for secure durable
integrated agents:

- RFC-0026 defines provider-neutral model inference;
- RFC-0027 defines bounded model turns and authorized tool calling;
- RFC-0028 defines durable agent runs and controlled resumption;
- RFC-0030 defines secure agent memory;
- RFC-0031 defines workspaces and artifacts;
- RFC-0032 defines host automation;
- RFC-0033 defines effective-authority non-amplification;
- RFC-0034 defines controlled network egress;
- RFC-0035 defines controlled browser automation;
- RFC-0036 composes integrated agent execution;
- RFC-0037 hardens crash, recovery, fencing, deadlines, budgets, and indeterminate
  external effects.

Those layers have intentionally relied heavily on deterministic, network-free
adapters for reliable testing.

That was appropriate while the contracts were being built, but it leaves a
different class of risk untested: real models and real provider transports behave
in ways deterministic fixtures do not.

A real model may:

- produce malformed or surprising output;
- propose a tool that is unavailable;
- generate arguments that fail strict schemas;
- produce multiple tool calls when Phoenix permits one;
- emit text and tool calls together;
- exceed expected response sizes;
- consume context unpredictably;
- time out or stream slowly;
- change behavior across model revisions;
- disappear while a durable run is active;
- return provider-specific finish and usage metadata;
- repeatedly choose an ineffective action;
- react to untrusted tool, browser, memory, or workspace content;
- expose provider-specific protocol edge cases.

A real provider may:

- refuse connections;
- terminate after receiving a request;
- return malformed JSON;
- return an incomplete stream;
- close a stream without a terminal result;
- become unavailable after admission;
- report usage inconsistently;
- replace a model behind a mutable model name;
- expose administrative operations that Phoenix must not implicitly acquire;
- behave differently after upgrade or restart.

Serious dogfood is therefore not an optional demonstration. It is the next source
of architectural evidence.

## Relationship to RFC-0026

RFC-0026 remains the sole provider-neutral inference authority boundary.

RFC-0038 MUST reuse:

- `ModelProviderId`;
- `ModelId`;
- `ModelDescriptor`;
- `InferenceRequest`;
- `InferenceResponse`;
- `InferenceChunk`;
- `InferenceUsage`;
- `InferenceLimits`;
- `ModelEndpointPolicy`;
- `ModelCredentialPolicy`;
- `ModelProvider`;
- `ModelProviderRegistry`;
- `InferenceRuntime`;
- `InferenceService`;
- exact `model.infer` authorization;
- endpoint admission;
- credential leasing where applicable;
- bounded complete and streaming execution;
- cancellation and deadline semantics;
- no-transparent-retry semantics;
- content-free inference observability.

RFC-0038 MUST NOT introduce an Ollama-specific authorization action.

RFC-0038 MUST NOT let a caller choose arbitrary model-provider URLs, credentials,
transport headers, process commands, or model management operations.

RFC-0038 MAY add narrowly scoped provider-adapter contracts or configuration needed
to bind a concrete reviewed transport to the existing RFC-0026 abstractions.

## Relationship to RFC-0027

RFC-0027 remains the sole normal model/tool loop.

Every model turn still produces exactly one of:

```text
FINAL_OUTPUT
```

or:

```text
TOOL_PROPOSAL
```

A real provider's native result is never a Phoenix tool invocation by itself.

Provider-native tool-call or structured-output formats may be decoded into an
`AgentModelTurnResult`, but RFC-0027 continues to own:

- admitted tool inventory;
- strict argument-schema validation;
- trusted tool lookup;
- concrete resource resolution;
- exact `tool.invoke` authorization;
- human approval when required;
- effect classification;
- bounded tool execution;
- tool-result validation;
- loop budgets and termination.

Multiple provider-native tool calls in one model turn fail closed unless a later
RFC explicitly changes the one-tool-per-turn invariant.

## Relationship to RFC-0036 and RFC-0037

RFC-0036 remains the integrated orchestration layer.

RFC-0037 remains the durability and recovery hardening layer.

Real-provider execution does not create another durable engine, checkpoint format,
recovery coordinator, task identity, or authority model.

After restart, current provider/model configuration wins over persisted historical
metadata. A durable run cannot resume model execution merely because the same
provider name became reachable again.

Recovery MUST revalidate current model/provider compatibility, current profile,
current tool set, current schemas, current policy, current deadlines and budgets,
and all other RFC-0037 evidence before fresh protected work.

An inference attempt whose external acceptance or completion is uncertain is not
silently replayed.

## Goals

- Execute real model inference through the existing RFC-0026 boundary
- Eliminate parallel agent-to-provider execution paths that bypass RFC-0026 controls
- Support a reviewed loopback-local provider without weakening endpoint policy
- Keep providers and models explicit, server-owned, and provider-neutral
- Bind Phoenix `ModelId` values to reviewed provider-native model names
- Detect configured-model unavailability without granting discovered models authority
- Support complete inference and bounded streaming
- Normalize provider-native usage and finish information into Phoenix contracts
- Support real RFC-0027 agent turns through one exact authorized inference path
- Provide a strict structured model-turn bootstrap before requiring native tool calling
- Allow reviewed native tool-call translation without changing RFC-0027 authority
- Reject multiple tool calls, mixed ambiguous outcomes, and malformed structured results
- Keep provider generation/resource options server-controlled
- Preserve no-transparent-retry behavior
- Preserve current cancellation and deadline behavior
- Preserve v0.37 durable recovery and live-revalidation rules
- Add content-free metrics useful for real-model dogfood
- Exercise development, research, and desktop/integrated task classes
- Use real failures and restart scenarios as dogfood evidence
- Keep ordinary CI and the release gate network-free and deterministic
- Preserve compatibility when real providers are omitted
- Preserve a dependency-minimal Phoenix core where practical
- Make provider replacement possible without modifying Phoenix agent semantics

## Non-goals

- Making Qwen, Ollama, OpenAI, or any other vendor part of Phoenix identity
- Turning Phoenix OS into a coding-only assistant
- Replacing RFC-0026 with provider SDK calls
- Replacing RFC-0027 with provider-native agent loops
- Letting provider-native tool calling execute tools directly
- Automatic provider or model discovery as authorization
- Automatic model installation
- Automatic model download or deletion
- Automatic Ollama installation, startup, shutdown, or upgrade
- Automatic hosted-provider account or credential provisioning
- Automatic fallback from local inference to a hosted provider
- Automatic fallback between hosted providers
- Transparent retry after provider execution begins
- Arbitrary shell execution
- Arbitrary filesystem access
- Unrestricted HTTP tools
- General-purpose Git mutation authority
- Automatic commit, push, merge, tag, or release operations by the initial dogfood profile
- Provider-controlled Phoenix policy
- Model-controlled endpoint, credential, proxy, TLS, DNS, or redirect policy
- Model-controlled context-window or resource-allocation settings
- Persisting raw prompts or responses by default
- Persisting raw provider protocol frames by default
- Sending Phoenix secrets, approvals, or authority evidence to a model
- Making a paid external provider a required CI dependency
- Requiring internet connectivity for ordinary Phoenix tests
- Benchmarking every available local model
- Building a model router before one real-provider path is proven
- Adding connector ecosystems before dogfood demonstrates a concrete need
- Redesigning Phoenix around one machine's hardware characteristics

## Terminology

- **Real provider:** a reviewed `ModelProvider` implementation that communicates
  with an external model runtime or hosted service rather than returning a
  deterministic fixture.
- **Provider-native model name:** the model identifier understood by the concrete
  provider, such as an Ollama model name.
- **Phoenix model ID:** the stable `ModelId` selected by trusted Phoenix
  configuration.
- **Model binding:** the trusted mapping between a Phoenix model ID and one
  provider-native model identity plus reviewed provider settings.
- **Model revision evidence:** provider-specific immutable or content-addressed
  evidence, when available, used to detect that the provider-native model changed
  behind the configured name.
- **Model-turn bridge:** the reviewed execution seam that binds an RFC-0027 model
  turn to the exact RFC-0026 inference request and current security context.
- **Structured model-turn envelope:** a Phoenix-owned bounded structured result
  representing either one final output or one tool proposal.
- **Dogfood profile:** trusted deployment configuration selecting existing Phoenix
  models, tools, limits, policy, memory/workspace inputs, and orchestration
  capabilities for one class of real tasks.
- **Real-provider canary:** an explicit non-CI test that executes a reviewed task
  against a real provider and records content-free operational evidence.

## Threat and failure model

RFC-0038 treats model/provider behavior and external timing as untrusted.

The implementation must address:

- a local process impersonating the configured loopback service;
- loopback hostname resolving unexpectedly;
- attempts to redirect provider traffic off loopback;
- ambient proxy configuration;
- provider model names changing or disappearing;
- mutable provider model tags pointing to different model bytes;
- provider responses identifying another model;
- malformed complete responses;
- malformed streaming records;
- duplicate, missing, or out-of-order stream records;
- provider connection refusal;
- provider termination before first byte;
- provider termination during streaming;
- provider timeout after request acceptance;
- cancellation while provider work may still be running;
- provider usage counts that are absent, inconsistent, or unexpectedly large;
- oversized provider output;
- provider error bodies containing prompt or model content;
- caller attempts to supply provider-native transport options;
- caller attempts to increase context or memory allocation;
- caller attempts to set provider endpoints or credentials;
- automatic model discovery expanding the configured model set;
- prompt injection requesting unregistered tools;
- tool-result injection requesting privileged actions;
- model output containing fabricated policy actions or resources;
- native parallel tool calls;
- mixed final text and tool calls;
- unknown tool names;
- malformed or deeply nested tool arguments;
- structured-output parser differentials;
- provider-specific JSON duplicate-key ambiguity;
- provider upgrade changing native tool-call shape;
- provider disappearance during a durable run;
- model removal during a durable run;
- model revision drift during downtime;
- current policy/profile/tool/schema changes during downtime;
- restart after model execution reached an uncertain external phase;
- accidental paid-provider use from CI;
- accidental cloud fallback of content intended for local execution;
- prompt/response leakage through logs, exceptions, metrics, health, or audit.

Installed provider adapters remain trusted Phoenix code.

The external model runtime, model output, provider responses, provider-reported
metadata, model discovery responses, usage reports, and all model-generated
structured data remain untrusted.

A loopback endpoint proves network locality under the RFC-0026 endpoint policy; it
does not by itself prove the operating-system identity of the process listening on
that port. Deployment guidance must describe this trust boundary accurately.

## Security invariants

1. RFC-0026 remains the only normal inference execution boundary.
2. RFC-0027 remains the only normal model/tool loop.
3. RFC-0036 remains the integrated orchestration layer.
4. RFC-0028/RFC-0037 remain the durable/recovery authority.
5. A real model gains no Phoenix authority from being real.
6. A model response remains untrusted data.
7. Provider-native tool calls remain untrusted data.
8. Provider discovery never registers or authorizes a model automatically.
9. Every real model is explicitly represented by trusted Phoenix configuration.
10. Every real model invocation still requires exact `model.infer` authorization.
11. Every tool invocation still requires exact `tool.invoke` authorization.
12. The model cannot choose an arbitrary provider endpoint.
13. The model cannot choose credentials.
14. The model cannot alter proxy, redirect, DNS, or TLS policy.
15. Plain HTTP remains permitted only by the existing explicit loopback-local policy.
16. The first Ollama deployment is loopback-only.
17. The reviewed Ollama port is explicit rather than inherited from the loopback
    policy's generic default.
18. Provider administrative APIs are not implied by inference authority.
19. Phoenix does not automatically install, start, stop, update, pull, create,
    push, or delete provider models.
20. A provider-native model name is not itself Phoenix authority.
21. Provider model discovery is diagnostic evidence only.
22. A discovered model absent from Phoenix configuration remains unavailable to
    Phoenix callers.
23. When immutable model revision evidence is configured, a mismatch fails closed.
24. Phoenix never rewrites an expected model revision automatically.
25. Request generation parameters are not forwarded wholesale into provider-native
    options.
26. Resource-sensitive provider options come only from trusted configuration.
27. Any request-controlled generation option uses an explicit bounded allowlist.
28. The effective output limit cannot exceed Phoenix's registered/request limits.
29. Provider response limits remain enforced by RFC-0026 even if the provider
    ignores its own limit request.
30. Provider-reported usage never grants authority.
31. Provider-reported finish reasons are normalized and validated before exposure.
32. A model turn produces one final output or one tool proposal, never both.
33. Multiple native tool calls fail closed in v0.38.0.
34. Unknown native tools fail closed.
35. Tool arguments pass through Phoenix strict schema validation before
    authorization.
36. The model never supplies the canonical policy resource.
37. A tool result remains untrusted input to later model turns.
38. No transparent retry occurs after provider execution begins.
39. Connection/setup retryability, where provably safe, never becomes an implicit
    retry loop.
40. Cancellation prevents new work and bounds local cleanup.
41. Provider disappearance does not crash or redefine the Phoenix runtime.
42. Provider return does not automatically resume a durable run.
43. Model return does not automatically resume a durable run.
44. Recovery revalidates the current provider and model binding.
45. Recovery revalidates immutable model revision evidence when configured.
46. Restart never creates additional model/tool budget.
47. Restart never creates a later deadline for an existing run.
48. An indeterminate model or tool effect is never silently replayed.
49. Automatic local-to-cloud fallback is disabled.
50. Hosted-provider use requires explicit provider/model configuration and authority.
51. Real-provider tests are not required for normal network-free unit/CI gates.
52. Paid provider calls cannot occur from the default test suite.
53. Prompt and response text remain excluded from normal audit, metrics, logs, and
    health.
54. Provider raw response bodies and tracebacks are not public Phoenix errors.
55. Dogfood-specific tools do not acquire ambient shell, filesystem, network,
    secrets, policy, or Runtime authority.
56. Coding dogfood does not redefine Phoenix core semantics around Git or one
    repository.
57. Compatibility without real-provider configuration remains equivalent to v0.37.0.
58. The package version remains `0.37.0` until the final v0.38.0 release slice.

## Real-provider execution seam

The main architecture task in this RFC is not the Ollama HTTP call.

It is preserving one exact execution path between RFC-0027 and RFC-0026.

Phoenix v0.37.0 constructs an `InferenceRequest` for each agent model turn and
performs `model.infer` authorization. The actual model-turn adapter, however, is a
separate execution abstraction designed around deterministic provider-neutral
results.

That separation is safe for deterministic test adapters, but a production adapter
must not create a second direct transport path that duplicates or bypasses
RFC-0026 execution controls.

This RFC therefore requires a reviewed model-turn execution seam with these
properties:

- one exact `AgentModelTurnRequest`;
- one exact `InferenceRequest`;
- one current `SecurityContext`;
- the same provider/model identity across both requests;
- the same finite deadline or a stricter effective deadline;
- no provider endpoint supplied by model content;
- execution through RFC-0026 authorization/admission/limits/cancellation;
- one resulting `AgentModelTurnResult`;
- no hidden second inference call;
- no direct provider call from an agent adapter that bypasses the inference runtime.

The exact additive Python contract is a Slice 1 implementation decision.

The implementation SHOULD avoid ambient security context, global provider
singletons, or adapter-private endpoint/credential authority.

A production model-turn path should conceptually be:

```text
AgentModelTurnRequest
        +
exact InferenceRequest
        +
current SecurityContext
        |
        v
reviewed model-turn execution bridge
        |
        v
RFC-0026 InferenceService / InferenceRuntime
        |
        v
ModelProvider
        |
        v
external model runtime
        |
        v
validated InferenceResponse
        |
        v
strict Phoenix model-turn decoder
        |
        +--> FINAL_OUTPUT
        |
        `--> one TOOL_PROPOSAL
```

## Bootstrap model-turn protocol

Native tool calling is useful but is not required to prove the first real
model-turn path.

The initial production path SHOULD first prove an inference-backed structured
model-turn protocol using ordinary RFC-0026 inference.

Trusted Phoenix code serializes the admitted tool descriptors into bounded model
context and requests one Phoenix-owned result envelope.

The conceptual envelope is:

```json
{
  "kind": "final",
  "content": "bounded assistant result"
}
```

or:

```json
{
  "kind": "tool",
  "tool": "registered.tool.id",
  "arguments": {}
}
```

The final implementation may use a versioned envelope and stricter field names,
but it MUST preserve these properties:

- exactly one terminal kind;
- no mixed final/tool alternative;
- exactly one tool identifier for a tool outcome;
- arguments encoded as bounded data;
- duplicate keys rejected;
- unknown fields rejected;
- non-finite numbers rejected;
- bounded nesting and width;
- bounded UTF-8 representation;
- unknown tool identifiers rejected;
- tool arguments still validated against the registered `ToolDescriptor`.

The set of admitted tools sent to the model must come only from the current trusted
tool registry/profile.

The structured model-turn protocol grants no execution authority.

## Native provider tool calling

After the inference-backed path is proven, a reviewed provider adapter MAY support
native tool calling.

Native support MUST be an alternate encoding of the same Phoenix semantics, not a
new tool runtime.

Translation is:

```text
Phoenix admitted ToolDescriptor
        |
        v
provider-native tool declaration
        |
        v
model/provider result
        |
        v
strict provider decoder
        |
        v
Phoenix ToolCallProposal
        |
        v
normal RFC-0027 validation/authorization/approval/execution
```

The provider adapter may translate names and schema syntax only when the mapping is
exact and reversible for the current admitted tool set.

Provider-native parallel tool calls are not accepted by v0.38.0.

A response containing more than one tool call fails closed.

A response mixing a tool call with ambiguous final output fails closed unless the
provider protocol has a reviewed unambiguous rule and Phoenix still emits only one
`AgentModelTurnResult`.

## Reference local provider: Ollama

The first real provider integration is a reviewed local Ollama adapter.

The initial deployment shape is conceptually:

```text
provider_id: ollama-local
endpoint: http://127.0.0.1:11434
endpoint mode: LOOPBACK_HTTP
credentials: none
```

The exact request path remains adapter-owned and must remain beneath the configured
endpoint policy.

The provider MUST NOT accept an endpoint from `InferenceRequest.parameters`,
messages, model output, tool output, or any caller-controlled content.

The provider MUST NOT use ambient HTTP proxy configuration.

Redirects remain disabled.

The provider adapter owns protocol translation only.

It does not own Phoenix model authorization, agent authorization, tool authority,
durable recovery, or policy.

## Provider/model binding

A Phoenix model remains identified by:

```text
(provider_id, model_id)
```

The provider-native model name is trusted deployment configuration.

An example dogfood binding is:

```text
provider_id: ollama-local
model_id: qwen3-coder-30b
provider_model_name: qwen3-coder:30b
```

The example is not a permanent Phoenix requirement.

The provider instance SHOULD be constructed from the same immutable reviewed model
descriptors used by inference composition so the adapter does not maintain an
independent mutable model-name registry.

Slice 2 decision: a real provider may implement the
`InferenceConfigurationBoundProvider` composition contract. Runtime composition
then requires the provider's exact `InferenceProviderConfiguration` and exact
`ModelDescriptor` set to match the reviewed `InferenceServiceConfiguration`
before registry construction. The Ollama provider uses this contract so its
provider-native model binding cannot drift from the model identity reviewed by
RFC-0026. Provider-specific digest evidence remains additional immutable
deployment evidence rather than universal model identity.

Unknown Phoenix model IDs fail closed.

A provider response cannot replace the configured Phoenix model ID.

## Model discovery and health

Provider model-list/show operations may be used for explicit startup validation,
health, or operator diagnostics.

They MUST NOT:

- register a model;
- enable a model;
- change policy;
- change a Phoenix model ID;
- change a provider-native model binding;
- download missing model weights;
- select a replacement model;
- expand an agent profile.

Health may report bounded content-free states such as:

```text
configured
available
unavailable
revision_mismatch
provider_unreachable
```

Public health should not expose arbitrary provider response bodies or filesystem
locations.

## Model revision evidence

Mutable provider model names create a dogfood-specific reliability risk.

If `qwen3-coder:30b` points to different model bytes after an upgrade or model
replacement, a durable run may otherwise observe a materially different model
under the same configured name.

When the provider exposes immutable/content-addressed model revision evidence, the
Ollama adapter SHOULD support a trusted expected revision/digest in deployment
configuration.

Conceptually:

```text
model_id: qwen3-coder-30b
provider_model_name: qwen3-coder:30b
expected_model_digest: <reviewed provider digest>
```

Startup, health checks, and durable live revalidation may compare current provider
evidence to the configured value.

A mismatch:

- does not auto-update configuration;
- does not silently select the new model;
- does not automatically resume durable work;
- fails the affected model binding closed until explicitly reviewed.

Revision evidence is provider-specific deployment evidence, not a new universal
Phoenix model identity requirement.

If a provider cannot supply stable revision evidence, Phoenix must describe the
weaker assurance accurately rather than inventing one.

## Provider lifecycle

The initial Ollama integration treats the Ollama process and model installation as
externally managed deployment dependencies.

Phoenix v0.38.0 does not:

```text
install Ollama
start Ollama
stop Ollama
upgrade Ollama
pull a model
create a model
push a model
delete a model
```

Provider process lifecycle and inference authority remain separate.

If Ollama is unavailable, affected inference fails safely while unrelated Phoenix
services remain healthy.

If Ollama later becomes available, new work may use it only after current
configuration and authorization pass normally.

Durable work follows RFC-0037 recovery and live revalidation rather than
auto-resuming merely because the endpoint returned.

## Provider transport

The initial adapter should avoid adding a large provider SDK dependency when the
required protocol surface is small and stable enough for a reviewed bounded
transport.

The exact transport implementation is a Slice 2 decision.

Regardless of implementation, transport MUST provide:

- finite connect/read/total timeouts;
- no ambient proxy use;
- no redirects;
- bounded request encoding;
- bounded response decoding;
- bounded streaming frame handling;
- cancellation propagation where supported;
- safe error normalization;
- no raw provider body in Phoenix public errors;
- exact reviewed endpoint usage;
- no automatic retry after execution begins.

If a new HTTP dependency is required, it SHOULD remain optional/provider-scoped
rather than becoming an unconditional dependency of deployments that do not use
real providers.

The existing dependency-free core is a design constraint worth preserving, not an
absolute prohibition when a reviewed transport genuinely requires a dependency.

## Provider request translation

`InferenceRequest` remains provider-neutral.

The Ollama adapter translates only reviewed fields.

Messages map from Phoenix roles to provider roles.

The registered `provider_model_name` supplies the provider-native model selection.

`max_output_tokens` is translated to the provider's bounded output-generation
control where available.

The effective provider output limit MUST NOT exceed the Phoenix request/model
limit.

Provider-native generation options are divided into two classes:

```text
trusted deployment options
request-allowlisted generation options
```

Resource-sensitive options such as context allocation, model residency, device
selection, or equivalent provider execution controls belong to trusted deployment
configuration.

`InferenceRequest.parameters` MUST NOT be copied wholesale into a provider-native
`options` object.

Any request-allowlisted parameter requires:

- explicit Phoenix-owned name;
- exact expected scalar type;
- finite supported range or enum;
- deterministic translation;
- no endpoint/credential/network effect;
- no resource-limit amplification beyond trusted configuration.

Unknown parameters fail closed or are rejected before provider execution; they are
not silently forwarded.

## Context and local resource policy

Advertised model context size is not automatically the configured Phoenix context
budget.

The dogfood deployment begins with a conservative finite context budget and raises
it only after observed memory, latency, and stability evidence.

The model cannot increase its own context allocation.

A larger provider capability never overrides a smaller Phoenix limit.

Resource policy is deployment-specific and must not be encoded as a universal
Phoenix requirement for the model family.

## Complete inference

For complete inference the provider:

1. validates the exact Phoenix model mapping;
2. uses only the reviewed endpoint and provider configuration;
3. encodes one bounded provider request;
4. executes once;
5. decodes one bounded provider response;
6. normalizes finish and usage metadata;
7. returns one `InferenceResponse`.

Provider response model names, timestamps, durations, or implementation metadata
are informational only unless an explicit trusted validation contract says
otherwise.

## Streaming

Provider streaming is translated into ordered Phoenix `InferenceChunk` values.

The adapter never exposes raw provider stream records to callers.

RFC-0026 remains responsible for validating:

- request/provider/model identity;
- chunk order;
- maximum chunk count;
- maximum chunk size;
- accumulated response size;
- one terminal record;
- usage bounds;
- deadline;
- first-byte timeout;
- total timeout.

A provider stream ending without enough information to produce one valid terminal
Phoenix record fails closed.

Partial text already observed does not become a successful terminal result.

## Usage and finish normalization

Provider usage information maps only to bounded `InferenceUsage` fields when the
provider supplies semantically compatible values.

Unknown or absent provider usage cannot be fabricated as authoritative accounting.

Provider token counts are useful operational evidence but remain untrusted
metadata for authorization.

Provider finish reasons map into the finite Phoenix finish-reason contract.

Unknown, contradictory, or malformed terminal information fails closed rather than
being exposed as an arbitrary provider-specific enum.

## Failure semantics

The provider adapter maps transport/protocol failures into safe Phoenix inference
errors.

Examples include:

```text
connection refused
provider unavailable
model unavailable
model revision mismatch
timeout
malformed provider response
malformed stream
limit exceeded
cancelled
provider execution failure
```

Not every internal diagnostic requires a new public error code.

Public errors remain stable and content-free.

Detailed local diagnostics may use bounded Phoenix-owned categories when necessary
without exposing prompt/response content or provider tracebacks.

## No transparent retry

RFC-0038 preserves RFC-0026/RFC-0027 no-transparent-retry semantics.

After provider execution begins, Phoenix does not silently retry because:

- the provider may already have consumed compute;
- a hosted provider may have charged the request;
- output may differ on a new invocation;
- tool selection may differ;
- durable attempt semantics may become ambiguous.

A pre-send connection failure may be classified as safe-to-retry evidence only
when the transport can prove no request body or credential-bearing authorization
was transmitted.

Even then, caller/coordinator policy controls whether a new explicit attempt is
created.

## Cancellation

Cancellation stops acceptance of new provider output and bounds cleanup.

Cancellation does not prove the external provider did no work.

For durable execution, an interrupted real-provider attempt follows the existing
attempt/reconciliation rules when external completion cannot be proven.

Provider-specific cancellation mechanisms are transport behavior, not proof of
remote rollback.

## Durable recovery

For a durable run containing real model execution, recovery revalidates at least:

- current `agent.resume` authority;
- current integrated profile generation;
- current provider registration;
- current Phoenix model registration;
- current provider-native model binding;
- configured model revision evidence where applicable;
- current tool registry;
- current tool schemas;
- current effect classifications;
- current resource resolvers;
- current policy;
- current approvals;
- current remaining budgets;
- original deadline;
- current protected-payload capability.

A provider or model being available again is only one piece of current evidence.

It never overrides stale authority or an indeterminate prior attempt.

## Hosted-provider canary

A hosted provider may be added after the local real-provider path is proven.

Its purpose in v0.38.x is architectural comparison, not automatic fallback.

A hosted canary should reuse the same:

- `InferenceRequest` contracts;
- model-turn bridge;
- agent profile;
- admitted tools;
- policy;
- task class;
- limits where comparable.

Hosted credentials MUST use the existing exact-version Phoenix secret-reference
and bounded credential-lease model.

Ambient environment variables may be supported only as an explicitly reviewed
deployment import/bootstrap mechanism if ever needed; they are not the canonical
runtime authority for a configured hosted provider.

The hosted canary is not required for normal CI or a network-free release gate.

The release must remain valid when no hosted provider is configured.

## No automatic local-to-cloud fallback

Local provider failure never silently redirects prompts, memory context, workspace
content, tool results, or task data to a hosted provider.

Any future fallback requires:

- explicit trusted configuration;
- explicit model/provider authorization;
- explicit data-flow review;
- compatible confidentiality policy;
- current provider availability evidence;
- bounded routing semantics.

RFC-0038 does not introduce that mechanism.

## Dogfood profiles

Serious dogfood must cover more than coding.

The initial matrix contains three task classes:

```text
development
research
desktop/integrated
```

These are deployment profiles, not new Phoenix core identities.

### Development profile

The development profile exercises real model reasoning against a bounded
repository workspace.

The initial tool surface should be narrow and resource-scoped.

Candidate tool families include:

```text
repo.list
repo.search
repo.read
repo.diff
repo.patch
test.pytest
test.ruff
test.mypy
git.status
git.diff
git.log
```

Exact names and contracts are Slice 4 implementation decisions.

Read tools receive repository/path resources resolved by trusted code.

Write tools are limited to the configured repository/workspace and require the
appropriate effect classification, authorization, and approval.

The initial autonomous surface does not include:

```text
git commit
git push
git merge
git tag
release publication
arbitrary PowerShell
arbitrary shell
arbitrary filesystem access
```

If dogfood proves a need for a broader operation, Phoenix should first ask whether
a narrow general capability solves the need.

### Research profile

The research profile should reuse existing controlled browser, network, memory,
and workspace capabilities rather than introduce a separate research engine.

The goal is to test:

- navigation/planning under untrusted web content;
- bounded data extraction;
- workspace artifact handling;
- memory/context retrieval;
- provider context pressure;
- prompt-injection resistance;
- final disclosure controls.

### Desktop/integrated profile

The desktop profile should reuse RFC-0032 host automation and RFC-0036 integrated
execution.

The goal is to test:

- real model decisions over controlled host capabilities;
- current host/resource resolution;
- approval boundaries;
- interruption/cancellation;
- recovery after provider or Phoenix restart;
- separation between observed screen/host data and authority.

The profile must not create an unrestricted desktop-control escape hatch.

## Dogfood workload policy

Dogfood tasks must be representative enough to produce failures.

A release candidate should include evidence from:

- at least one multi-turn development task;
- at least one multi-step research task;
- at least one controlled desktop/integrated task;
- at least one provider-unavailability scenario;
- at least one cancellation scenario;
- at least one restart/recovery scenario;
- at least one rejected malformed/unauthorized tool proposal.

The exact task content is not committed to audit/log output by default.

Dogfood evidence records content-free outcome and operational metadata.

## Deliberate failure scenarios

The v0.38 dogfood plan should intentionally exercise:

- Ollama absent at startup;
- Ollama becoming unavailable before first byte;
- Ollama becoming unavailable during a stream;
- configured model missing;
- configured model revision mismatch;
- provider returning malformed JSON;
- provider returning oversized output;
- model returning unknown tool;
- model returning invalid tool arguments;
- model returning multiple tool calls;
- model repeatedly proposing an ineffective tool until budget exhaustion;
- cancellation during inference;
- cancellation during a tool call;
- Phoenix restart before a model attempt;
- Phoenix restart after a model attempt became uncertain;
- provider restored after Phoenix restart;
- model restored after Phoenix restart;
- policy tightened during downtime;
- tool removed during downtime;
- tool schema changed during downtime;
- profile generation changed during downtime;
- deadline expiring while Phoenix is offline;
- nearly exhausted budget across restart.

The expected result is controlled failure/recovery evidence, never silent
authority expansion or replay.

## Observability

Real-model dogfood needs more operational evidence than deterministic tests.

Content-free inference/agent observations may include:

- provider ID;
- Phoenix model ID;
- configured model-binding revision identifier/digest when safe and bounded;
- invocation mode;
- first-byte latency;
- total provider latency;
- input-token count when supplied;
- output-token count when supplied;
- bounded throughput derived from safe timing/usage facts;
- model turns per run;
- tool proposals per run;
- accepted/rejected proposal counts;
- timeout count;
- cancellation count;
- provider-failure category;
- durable recovery disposition;
- task terminal category.

The following remain excluded by default:

- prompt text;
- response text;
- reasoning text;
- tool arguments;
- tool results;
- browser content;
- workspace contents;
- memory contents;
- clipboard contents;
- credentials;
- approval evidence;
- raw provider bodies;
- raw provider protocol frames.

Dogfood debugging that requires content capture must use a separate explicit
reviewed mechanism; it cannot silently weaken default observability policy.

## Packaging and dependency policy

Phoenix OS v0.37.0 has no unconditional runtime dependency.

RFC-0038 should preserve a small provider-neutral core where practical.

Provider integrations MAY be:

- optional extras;
- reviewed integration packages;
- explicitly installed adapters;
- a narrowly scoped internal provider module with an optional transport dependency.

Slice 1 must decide the packaging model before adding a new unconditional runtime
dependency.

Slice 1 decision: the provider-neutral core remains dependency-free. Real-provider
adapters are provider-scoped integrations composed explicitly through RFC-0026. If
Slice 2 requires a third-party transport dependency, it must remain behind an
optional provider-specific installation boundary rather than becoming an
unconditional `phoenix-os` runtime dependency. Slice 1 itself adds no provider SDK
or transport dependency.

Provider discovery never implies automatic package installation.

The Plugin System may be used as an installation/composition boundary only when
doing so preserves the stricter RFC-0026 provider registration and authority
requirements.

A plugin manifest is not a substitute for model/provider authorization.

## Configuration

Real-provider configuration remains explicit.

Configuration should contain only trusted bounded values needed for the provider
and model binding.

A conceptual local deployment contains:

```text
provider:
  id: ollama-local
  endpoint: http://127.0.0.1:11434
  endpoint_mode: loopback_http
  allowed_ports: [11434]

model:
  id: qwen3-coder-30b
  provider: ollama-local
  provider_model_name: qwen3-coder:30b
  expected_model_digest: <optional reviewed digest>
  context_budget: <trusted bounded deployment value>
  generation_options: <reviewed bounded values>
```

This is conceptual configuration, not a frozen file format.

No example configuration grants policy permission automatically.

## Compatibility

With real-provider and real-agent dogfood configuration omitted:

- existing deterministic inference remains valid;
- existing deterministic agent tests remain valid;
- existing Runtime composition remains valid;
- no provider process is contacted;
- no network activity is introduced;
- no model is installed;
- no credential is created;
- no new tool is registered;
- no additional authority is granted;
- v0.37 durable/recovery behavior remains unchanged.

The package version remains `0.37.0` throughout implementation slices.

The version changes to `0.38.0` only in the final release slice after all required
gates and dogfood evidence pass.

## Test strategy

The ordinary automated test suite remains deterministic and network-free.

Real-provider code requires protocol-level tests using deterministic local fakes
that simulate:

- valid complete response;
- valid streaming response;
- malformed JSON;
- duplicate fields;
- missing terminal fields;
- oversized response;
- connection failure;
- timeout;
- cancellation;
- truncated stream;
- unexpected model identity metadata;
- missing configured model;
- revision mismatch;
- multiple tool calls;
- unknown tool;
- malformed arguments;
- mixed final/tool result.

No normal test may require Ollama to be installed.

No normal test may download model weights.

No normal test may spend hosted-provider credits.

Real Ollama and hosted-provider canaries are separate explicit dogfood procedures.

## Release-gate expectations

The v0.38.0 release gate must include at least:

- all pre-existing project quality gates;
- RFC-0026 inference security/regression tests;
- RFC-0027 agent security/regression tests;
- RFC-0028 durable-run tests;
- RFC-0036 integrated-agent tests;
- RFC-0037 reliability/adversarial tests;
- deterministic real-provider transport/codec tests;
- deterministic model-turn bridge tests;
- deterministic malformed-native-result tests;
- deterministic provider-unavailability tests;
- deterministic model-binding/revision tests;
- compatibility tests with real providers omitted;
- package build and isolated install validation;
- proof that release tests require no external network/model/API;
- a separately recorded manual/operational dogfood checklist for real-provider
  execution.

A real-provider canary failure blocks release when it demonstrates a Phoenix
contract violation.

A canary failure caused solely by a documented external provider outage may be
classified separately, but must not be converted into a passing Phoenix result.

## Slice plan

### Slice 1 - Real-provider model-turn execution seam

- [x] Freeze the exact RFC-0027 turn to RFC-0026 inference binding
- [x] Ensure one real model turn executes through RFC-0026 rather than a parallel provider path
- [x] Bind exact provider/model/deadline/security context across the seam
- [x] Add a strict versioned structured model-turn envelope
- [x] Add deterministic inference-backed agent-turn adapter/executor tests
- [x] Preserve the deterministic `AgentModelTurnAdapter` test path
- [x] Prove no agent model-turn path gains endpoint or credential authority
- [x] Decide provider-integration packaging/dependency boundary
- [x] Keep package version at 0.37.0

### Slice 2 - Ollama loopback provider

- [x] Add reviewed `OllamaModelProvider`
- [x] Add immutable trusted model binding configuration
- [x] Use explicit RFC-0026 loopback endpoint policy and port 11434
- [x] Add complete inference translation
- [x] Add bounded streaming translation
- [x] Add finish and usage normalization
- [x] Add provider/model availability diagnostics
- [x] Add optional reviewed model revision/digest validation
- [x] Reject model-management operations and dynamic model authority
- [x] Reject ambient proxy/redirect behavior
- [x] Reject unreviewed provider-native request options
- [x] Add deterministic fake-server protocol tests
- [x] Keep package version at 0.37.0

### Slice 3 - Real agent turns and provider-native translation

- [ ] Run real structured model turns through the inference-backed path
- [ ] Translate admitted tool descriptors into bounded model context
- [ ] Decode one final output or one tool proposal
- [ ] Reject mixed outcomes and multiple tool proposals
- [ ] Validate unknown/malformed tool data before authorization
- [ ] Evaluate native Ollama tool-calling only after the structured path is green
- [ ] If native tool calling is added, prove semantic equivalence to RFC-0027
- [ ] Add cancellation, timeout, malformed-result, and budget tests
- [ ] Keep package version at 0.37.0

### Slice 4 - Minimal real-task dogfood profiles

- [ ] Add/reuse a bounded development profile
- [ ] Add only narrow repository/test tools proven necessary by dogfood
- [ ] Keep unrestricted shell and filesystem access excluded
- [ ] Keep commit/push/merge/tag/release outside the initial autonomous tool set
- [ ] Add/reuse a research profile using existing browser/network/workspace/memory boundaries
- [ ] Add/reuse a desktop/integrated profile using existing host/orchestration boundaries
- [ ] Prove profiles do not alter core provider-neutral semantics
- [ ] Keep package version at 0.37.0

### Slice 5 - Durable real-provider dogfood and failure matrix

- [ ] Run representative real local-model tasks
- [ ] Exercise provider/model disappearance
- [ ] Exercise cancellation during real inference
- [ ] Exercise restart around model attempts
- [ ] Exercise current provider/model/profile/tool/schema/policy revalidation
- [ ] Exercise model revision drift where provider evidence is available
- [ ] Prove no replay of indeterminate external attempts
- [ ] Prove deadline and budget continuity
- [ ] Record content-free dogfood evidence
- [ ] Keep automated CI network-free
- [ ] Keep package version at 0.37.0

### Slice 6 - Dogfood hardening and optional cross-provider canary

- [ ] Fix only general problems demonstrated by real dogfood
- [ ] Harden provider health and operator diagnostics
- [ ] Harden latency/usage/content-free model observations
- [ ] Review configuration ergonomics without adding ambient authority
- [ ] Optionally add one hosted-provider canary behind RFC-0026
- [ ] If a hosted provider is added, use exact Phoenix secret leasing
- [ ] Prove there is no automatic local-to-cloud fallback
- [ ] Compare equivalent tasks without changing AgentLoop/tool authority
- [ ] Keep paid/network canaries outside mandatory CI
- [ ] Keep package version at 0.37.0

### Slice 7 - v0.38.0 release gate and finalization

- [ ] Run the complete existing quality gate
- [ ] Run RFC-0038 deterministic provider and model-turn gates
- [ ] Run RFC-0037 adversarial reliability gate
- [ ] Complete real development/research/desktop dogfood checklist
- [ ] Review all dogfood-discovered security and reliability issues
- [ ] Build wheel and sdist
- [ ] Validate isolated offline installation
- [ ] Verify no provider/model/API is required by package import or normal tests
- [ ] Write release notes and migration/dogfood guidance
- [ ] Change package version from 0.37.0 to 0.38.0 only here
- [ ] Mark RFC-0038 Accepted only after all required evidence is green
- [ ] Tag and publish only after the normal release authorization/gates

## Acceptance criteria

RFC-0038 may be accepted for Phoenix OS v0.38.0 only when all of the following are
true:

1. At least one real model provider executes through the reviewed RFC-0026 boundary.
2. The RFC-0027 production model-turn path does not bypass RFC-0026 execution controls.
3. Real agent turns terminate as exactly one final output or one tool proposal.
4. Provider-native or structured model output has no authority by itself.
5. Multiple tool proposals fail closed.
6. Provider/model discovery cannot expand configured authority.
7. The local reference provider is constrained to reviewed loopback policy.
8. Provider options cannot amplify trusted resource limits through caller data.
9. Provider/model disappearance produces controlled bounded failure.
10. Model revision drift is detected when configured provider evidence makes that
    detection possible.
11. No automatic provider failover or local-to-cloud fallback exists.
12. No transparent retry occurs after provider execution begins.
13. Real-provider cancellation follows existing bounded cancellation semantics.
14. Durable recovery revalidates current provider/model/profile/tool/policy evidence.
15. Indeterminate external model/tool attempts are not silently replayed.
16. At least one real development task completes under Phoenix authority.
17. At least one real research task exercises existing general capabilities.
18. At least one controlled desktop/integrated task exercises existing host boundaries.
19. Deliberate provider failure and restart scenarios have content-free dogfood evidence.
20. No dogfood profile requires unrestricted shell, unrestricted filesystem, or
    unrestricted HTTP authority.
21. Normal tests and the release gate remain deterministic and network-free.
22. No normal CI job downloads a model or spends hosted-provider credits.
23. Compatibility without real-provider configuration is preserved.
24. Prompt/response/tool content remains excluded from normal observability by default.
25. Package artifacts install and import without requiring Ollama or a hosted-provider SDK.
26. The package version changes to 0.38.0 only in the final release slice.
27. Any broader feature discovered during dogfood is deferred unless it is necessary
    to satisfy these acceptance criteria safely.

## Post-v0.38 direction

RFC-0038 intentionally does not freeze Phoenix OS v0.39.0.

The purpose of serious integrated dogfood is to replace speculative roadmap work
with operational evidence.

Potential v0.39 work may include configuration, diagnostics, provider routing,
additional safe tools, connector work, performance, context management, model
selection, or other usability/reliability improvements.

None of those becomes committed scope merely because it is plausible before
dogfood.

The dominant post-v0.38 rule is:

> **Generalize from repeated real need; do not redesign Phoenix around one model,
> provider, benchmark, or application.**
