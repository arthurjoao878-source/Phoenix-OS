# ADR-0011: Provider-neutral contracts and reviewed inference registry

- **Status:** Accepted
- **Date:** 2026-07-27
- **Related RFC:** [RFC-0026](../rfcs/RFC-0026-secure-model-providers-and-inference-runtime.md)

## Context

Provider SDK objects, remote model names, request formats, streaming frames, and
errors vary by vendor. Allowing callers to pass those values directly would
couple Phoenix features to provider transport and allow unreviewed endpoints,
credentials, or models to enter the trusted execution path.

## Decision

Phoenix owns immutable provider-neutral contracts including
`InferenceRequest`, `InferenceResponse`, `InferenceChunk`, `InferenceUsage`,
`ModelProviderId`, `ModelId`, `ModelDescriptor`, and finite limits.

`ModelProviderRegistry` is the allowlisting boundary. Providers and models are
registered from trusted configuration before inference is accepted. The registry
rejects duplicates, missing registrations, incompatible capabilities, and
configuration/provider mismatches.

Callers select only stable Phoenix provider and model identifiers. Callers
cannot supply endpoint, credential, proxy, DNS, TLS, arbitrary transport header,
provider SDK object, or unregistered remote model.

Provider-private model names and compatibility metadata remain inside trusted
configuration and adapter boundaries. Raw provider streaming frames and errors
are converted to Phoenix-owned contracts and safe categories.

The package includes a deterministic network-free provider for tests and
migration validation. Hosted-provider and local-model adapters remain optional
integrations behind the same contracts.

## Consequences

Positive consequences:

- Phoenix features remain independent of one provider SDK;
- provider/model selection is explicit and reviewable;
- unregistered remote models cannot be discovered or invoked by callers;
- limits and validation apply consistently across adapters;
- tests require no network, credential, or paid provider usage.

Costs and constraints:

- adapters must translate provider formats into Phoenix contracts;
- configuration must register every provider and model explicitly;
- provider-specific features are unavailable until represented by a reviewed
  provider-neutral contract;
- adapter code remains trusted installed code and requires review.

## Alternatives considered

### Pass provider SDK request and response objects through Phoenix

Rejected because it couples authority, secrets, errors, and observability to one
vendor and bypasses common validation.

### Discover remote models automatically

Rejected because remote inventory is not a reviewed allowlist.

### Let callers provide endpoint URLs and provider model names

Rejected because caller-selected transport and model identity would bypass
trusted configuration.

### Define one contract per provider

Rejected because common policy, limits, streaming, cancellation, and safe errors
would diverge.

## Supersession criteria

A future ADR may replace these contracts only if provider/model allowlisting
remains server-side, callers still cannot supply transport authority, all
request and response dimensions remain bounded, and adapters continue to expose
only Phoenix-owned safe contracts.
