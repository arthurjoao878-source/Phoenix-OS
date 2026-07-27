# ADR-0012: Exact inference authorization and untrusted model output

- **Status:** Accepted
- **Date:** 2026-07-27
- **Related RFC:** [RFC-0026](../rfcs/RFC-0026-secure-model-providers-and-inference-runtime.md)

## Context

Inference can consume credentials, network capacity, provider quota, and money.
Model output may also resemble commands, policies, URLs, tool requests, or
structured instructions. A broad "AI access" permission or implicit trust in
output would cross Phoenix authority boundaries.

## Decision

Every invocation requires central default-deny policy approval for the exact
`model.infer` action and the concrete resource
`model-provider:<provider-id>/model:<model-id>`.

Authorization permits only one bounded request to reach that registered model.
It never grants capability, command, job, workflow, plugin, webhook,
inbound-event, filesystem, shell, network, or operating-system authority.

Model output is untrusted data. Complete text, streamed chunks, JSON-like
content, finish reasons, and usage reports cannot authorize or execute an
action. Any subsystem that may act on model output must validate it as untrusted
input and perform a new independent policy decision for its own exact action and
resource.

Provider usage facts are bounded observation metadata and are not trusted for
authorization. Generic denial behavior avoids provider and model enumeration.

## Consequences

Positive consequences:

- inference access is least-privilege and model-specific;
- model output cannot inherit the caller's Phoenix authority;
- later agent or tool RFCs must define a separate authorization boundary;
- provider existence is not disclosed through authorization differences;
- policy review can distinguish principals, providers, and models.

Costs and constraints:

- policy configuration is explicit;
- changing a provider or model identifier requires policy review;
- applications must treat output parsing and action authorization as separate
  steps;
- one successful inference does not imply permission to retry or invoke another
  model.

## Alternatives considered

### Grant inference through one global wildcard permission

Rejected because it prevents model-specific least privilege and increases
provider-enumeration risk.

### Treat structured model output as an approved command

Rejected because generated content is not identity, policy evidence, or trusted
code.

### Reuse capability or command permission for inference

Rejected because sending a bounded model request and executing a privileged
Phoenix action are different authorities.

### Let the adapter decide authorization

Rejected because provider code must not replace the central Policy Engine.

## Supersession criteria

A future ADR may change the action or resource scheme only if every invocation
still receives a central concrete decision, generic denial remains
non-enumerating, and model output continues to receive no implicit authority.
