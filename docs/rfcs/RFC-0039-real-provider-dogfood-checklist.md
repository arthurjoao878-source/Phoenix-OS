# RFC-0039 Real-Provider Dogfood Checklist

This checklist is normative release evidence for Phoenix OS v0.39.0. It is intentionally
separate from ordinary deterministic CI.

RFC-0039 remains Proposed until this checklist and the final release gate are reviewed green.

## Safety and authority rules

- Use an official v0.39 candidate wheel installed into a clean virtual environment.
- Do not import Phoenix from the source tree during normal-path dogfood.
- Do not use a custom Python composition helper.
- Keep provider process lifecycle and model inventory operator-controlled.
- Use explicit reviewed provider/model/profile and development-checkout configuration.
- Grant no shell or Git authority for the normal task path.
- Keep routine evidence content-free.

## Environment readiness

Record content-free identities for the candidate wheel, Python environment, reviewed
configuration digest, selected provider/model identity, checkout registration identity, and
Phoenix task/run identity. Do not record prompts, model output, tool payloads, workspace file
contents, credentials, or other secrets.

## Required real workload evidence

- [ ] Candidate wheel installs with no source-tree import.
- [ ] `phoenix config validate` succeeds for explicit reviewed local provider/model/profile configuration.
- [ ] With Ollama stopped, `phoenix doctor` reports `provider_unreachable` without mutation.
- [ ] Operator starts Ollama manually.
- [ ] `phoenix doctor` reports the configured model as available.
- [ ] `phoenix task run` starts a real-model task through the normal integrated path.
- [ ] The task uses bounded `workspace.list` / `workspace.read` beneath configured `read_prefixes`.
- [ ] Each checkout read creates current-run freshness evidence and consumes finite read budget.
- [ ] The model proposes a bounded patch to a file it actually observed.
- [ ] Phoenix renders the trusted bounded diff.
- [ ] Required approval binds to that exact prepared patch.
- [ ] Phoenix applies the patch and reports before/after digests.
- [ ] A stale-base or unobserved-base patch is rejected.
- [ ] A traversal, reparse, or special-file patch attempt is rejected.
- [ ] A `.git`, active-config, or other protected-target patch attempt is rejected.
- [ ] Provider interruption produces controlled failure.
- [ ] Stop/restart plus `phoenix task resume` follows RFC-0037 live revalidation.
- [ ] Task status reports finite budgets and terminal reason.
- [ ] No shell or Git authority is used.
- [ ] Normal evidence remains content-free.

## Recommended normal-task sample

Before publication, exercise 10-20 normal tasks across more than one task shape and review any
security, reliability, usability, or recovery issue discovered by that sample.

## Per-run record template

Record only content-free fields:

- candidate wheel SHA256;
- Phoenix version;
- configuration digest;
- provider/model identity metadata;
- task/run identifier;
- admitted checkout identifier;
- bounded operation/result classification;
- approval/review state;
- before/after digests where the product normally exposes them;
- budget/deadline/terminal reason;
- pass/fail disposition and reviewed issue reference.

## Closure

Do not mark an item complete without operator-observed evidence from the official candidate wheel
and official entrypoints. Completing this checklist does not by itself authorize commit, push,
tag, publication, or RFC acceptance; those decisions remain separate reviewed gates.
