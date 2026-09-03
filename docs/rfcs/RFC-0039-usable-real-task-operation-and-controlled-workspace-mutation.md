# RFC-0039: Usable Real-Task Operation and Controlled Workspace Mutation

- Status: Proposed
- Target release: Phoenix OS v0.39.0
- Owners: Phoenix OS maintainers
- Depends on: RFC-0005, RFC-0006, RFC-0009, RFC-0012, RFC-0020, RFC-0021, RFC-0026, RFC-0027, RFC-0028, RFC-0031, RFC-0033, RFC-0036, RFC-0037, and RFC-0038
- Baseline: Phoenix OS v0.38.0, `main` at `096ccb921790acd84b66cde02ca218921e97a8bc`

## Summary

RFC-0039 turns the real-model engine proven by RFC-0038 into an operator-usable path for
normal tasks without adding a second agent loop, weakening existing authority boundaries,
or requiring one-off Python composition scripts.

Phoenix OS v0.38.0 can install cleanly, import cleanly, execute a reviewed local Ollama
provider, and run integrated real-model dogfood through the existing RFC-0026, RFC-0027,
RFC-0036, and RFC-0037 boundaries. Post-release dogfood nevertheless found a product-level
blocker: an operator who installs the official wheel cannot configure a model, diagnose the
runtime, or start a normal task through the packaged `phoenix` interface. The only packaged
CLI surface is authority inspection, while real task composition remains a low-level Python
assembly exercise.

This RFC therefore introduces two operator-facing capabilities and one narrowly bounded new
mutation capability:

1. an official task/configuration/diagnostic entrypoint over the existing runtime;
2. observable, content-free task state and budget diagnostics;
3. an opt-in `workspace.patch` capability for controlled mutation of explicitly registered
   development checkout workspaces.

The dominant rules are:

> **Usability is not a new authority boundary. The operator entrypoint must compose existing
> Phoenix services instead of bypassing them.**

> **Discovery may inform diagnostics, but discovered providers, models, paths, or tools never
> become authorized configuration automatically.**

> **A development checkout is a trusted, explicitly registered root. The model sees only
> Phoenix logical paths and can never select an arbitrary host path.**

> **Every patch is stale-safe, bounded, reviewable, independently authorized, and committed
> only after final path, digest, policy, and approval revalidation.**

> **The v0.39 release gate is not satisfied by a custom helper script. The official wheel must
> configure, diagnose, run, patch, review, and finish a real task through normal product
> interfaces.**

## Motivation

RFC-0038 intentionally proved the engine before optimizing product ergonomics. That order was
correct: real providers and real models first had to pass through Phoenix's existing security,
durability, recovery, and tool-authority boundaries.

After publication of v0.38.0, a clean-wheel dogfood session was performed from the perspective
of a normal local operator rather than a test harness author.

### Post-release dogfood evidence

The dogfood used the official v0.38.0 wheel in an isolated Python 3.12 virtual environment.
No source-tree import was required for installation or package import.

#### D0 - clean install and public entrypoint

Observed:

- Python 3.12.0 available;
- official `phoenix_os-0.38.0-py3-none-any.whl` installed successfully with `--no-deps`;
- `phoenix-os` reported version `0.38.0`;
- `import phoenix_os` succeeded;
- packaged `phoenix --help` exposed only the `authority` command;
- `phoenix authority --help` exposed only `inspect` and `explain`.

Conclusion:

- package installation is usable;
- normal task execution is not discoverable or exposed through the official entrypoint.

#### D1 - provider, model, config, doctor, and task discovery

Observed:

- `phoenix provider --help` returned invalid arguments;
- `phoenix model --help` returned invalid arguments;
- `phoenix config --help` returned invalid arguments;
- `phoenix doctor --help` returned invalid arguments;
- `phoenix task --help` returned invalid arguments;
- Ollama was installed locally, but initially no service was reachable on the reviewed
  `127.0.0.1:11434` endpoint;
- Phoenix exposed no normal operator diagnostic that explained this condition.

Conclusion:

- RFC-0038 already has provider diagnostics internally, but the packaged product lacks an
  operator-facing configuration and doctor experience.

#### D2 - provider readiness

After the operator manually started Ollama, as required by RFC-0038's non-goals:

- `127.0.0.1:11434` became reachable;
- Ollama client version `0.33.2` was present;
- an existing local model, `qwen3:4b-instruct`, was listed;
- no model was automatically downloaded or authorized by Phoenix.

Conclusion:

- the reviewed provider environment was available without any need to weaken RFC-0038;
- the next blocker was Phoenix configuration, not provider installation.

#### D3 - model binding through the installed product

Observed from the installed wheel:

- no `phoenix config` command exists;
- binding a real local model requires manual construction of low-level objects including
  `InferenceProviderConfiguration`, `InferenceServiceConfiguration`, `ModelDescriptor`,
  `ModelEndpointPolicy`, `OllamaModelBinding`, and `OllamaModelProvider`;
- continuing to a real task would therefore require a custom Python composition helper.

Conclusion:

The normal-user dogfood stopped at D3. Continuing with a one-off helper would measure internal
API composability, which RFC-0038 already proved, instead of product usability.

This is the direct evidence base for RFC-0039.

## Scope decision

v0.39.0 must solve the blockers actually observed before adding unrelated authority.

The release scope is:

- **P0:** official task entrypoint;
- **P0:** operational configuration and `doctor`;
- **P0:** content-free task/budget status;
- **P1:** controlled `workspace.patch` for explicitly registered development checkouts;
- **P1:** trusted patch review/diff;
- **P0 release gate:** real dogfood from the official wheel with no custom composition helper.

Git mutation, arbitrary shell, generic filesystem write, cloud routing, desktop-wide control,
and connector expansion remain outside this release.

## Relationship to RFC-0005 configuration

RFC-0005 remains the configuration composition boundary.

RFC-0039 may add an operator-facing configuration document and loader, but it must compile into
existing typed Phoenix configuration objects. It must not introduce a parallel configuration
truth source that bypasses typed validation, provenance, or server-owned defaults.

Configuration files are operator input, not model input. A model cannot rewrite the active
provider, model, profile, workspace root, endpoint, credential reference, authority rule, or
resource limit merely because a task mentions a different value.

## Relationship to RFC-0026 and RFC-0038 inference

RFC-0026 remains the only provider-neutral inference boundary.

RFC-0038 remains the reviewed real-provider path.

The operator task entrypoint must ultimately invoke the same `InferenceService` and same
provider/model registry used by existing agent execution. It must not call Ollama, OpenAI, or
another provider directly.

Provider discovery is diagnostic only. In particular:

- an Ollama model returned by `/api/tags` does not become configured;
- a model name found on disk does not become authorized;
- a reachable endpoint does not become trusted unless current configuration admits it;
- a future hosted-provider credential found in the environment does not become authority.

## Relationship to RFC-0027, RFC-0028, RFC-0036, and RFC-0037

RFC-0027 remains the normal model/tool loop.

RFC-0028 remains the durable run/checkpoint and controlled resumption boundary.

RFC-0036 remains the integrated task orchestration layer.

RFC-0037 remains the recovery and reliability hardening layer.

RFC-0039 introduces no second task state machine. `phoenix task run` is an operator entrypoint
that assembles and invokes the existing integrated task service. `phoenix task resume` must use
RFC-0028/RFC-0037 recovery and live revalidation rather than replaying or reconstructing a new
run from CLI state.

## Relationship to RFC-0031 workspaces

RFC-0031 remains the core workspace/artifact authority model and its principle remains valid:
files carry data, never authority.

RFC-0039 adds one explicit development-only adapter category: a **registered checkout-backed
workspace**.

This does not make native host paths model resources. Instead:

- the operator configures one trusted absolute root;
- Phoenix assigns a stable workspace identity and server-owned name;
- the model and tool layer receive only canonical Phoenix logical paths;
- all resolution occurs beneath the configured root;
- symlink, junction, reparse-point, hardlink, special-file, traversal, alias, and TOCTOU escape
  attempts fail closed;
- no other host path becomes reachable.

A checkout-backed workspace is opt-in and must not change existing RFC-0031 behavior when
omitted.

## Goals

- Make the official wheel usable for a normal real-model task without custom Python composition
- Preserve the existing `phoenix authority` CLI behavior
- Add an official operator task entrypoint over RFC-0036
- Add explicit operator configuration that compiles into existing typed configuration
- Add a content-free `phoenix doctor` diagnostic path
- Diagnose configured provider reachability and configured model availability
- Keep provider/model selection explicit and server-owned
- Keep discovered providers/models non-authoritative
- Support normal task start, status, cancellation, and durable resume through existing services
- Avoid raw prompt text in process arguments and normal observability
- Expose reliable task/run/step/tool/deadline/budget state without inventing unknown values
- Add an opt-in development checkout registration boundary
- Add one narrow `workspace.patch` action for existing bounded UTF-8 text files
- Require expected base digest for every patch
- Require patch preparation and final commit revalidation
- Render a trusted bounded diff before approval or commit when policy requires review
- Reject stale, escaped, binary, special, oversized, or ambiguous targets
- Record content-free before/after mutation evidence
- Keep ordinary CI deterministic and network-free
- Require final real-provider dogfood from an installed official candidate wheel without helpers

## Non-goals

- Arbitrary shell, PowerShell, cmd.exe, bash, or command execution
- Generic `filesystem.write`
- Arbitrary native filesystem paths supplied by a model
- Automatic project-tree discovery or mounting
- Automatic provider installation, startup, shutdown, upgrade, model pull, or model deletion
- Automatic provider/model authorization from discovery
- Automatic local-to-cloud fallback
- Automatic fallback between models or providers
- Hosted-provider routing or cost optimization
- A model router
- Git staging, commit, push, merge, tag, release, or branch deletion
- Generic repository mutation authority outside `workspace.patch`
- File delete, rename, move, chmod, ACL mutation, ownership mutation, or executable-bit changes
- Binary patching
- Archive extraction
- Arbitrary script execution after patching
- Automatic test execution after patching
- Generic mouse/keyboard control
- New browser or network authority
- Secret storage inside the operator configuration document
- Persisting prompts, responses, reasoning, tool arguments, tool results, file contents, or diffs in
  normal logs/audit
- Making Ollama or any specific model part of Phoenix identity
- Replacing RFC-0031 with ambient host-filesystem access

## Operator CLI

The packaged `phoenix` entrypoint remains one command and gains finite reviewed subcommands.

The initial v0.39 surface is:

```text
phoenix
├─ authority ...                 # existing RFC-0033 surface
├─ config init
├─ config validate
├─ config show
├─ doctor
└─ task
   ├─ run
   ├─ status
   ├─ cancel
   └─ resume
```

No generic plugin-defined arbitrary CLI command namespace is introduced by this RFC.

### Task input

`phoenix task run` must not require raw task text in a command-line argument.

The supported task-input modes are:

- interactive hidden-from-argv stdin entry; or
- ordinary stdin piping.

A future reviewed file-input mode may be added, but v0.39 does not need one.

The task text is untrusted task data. It cannot select provider endpoints, credentials, native
host paths, policy rules, hidden tools, or authority.

### Task run

A representative invocation is:

```text
phoenix task run --profile development --workspace project
```

The names `development` and `project` are trusted configuration references, not arbitrary native
resources.

The command must:

1. load and validate operator configuration;
2. assemble the existing Phoenix Runtime composition;
3. resolve one configured integrated profile;
4. resolve one configured model binding;
5. resolve one configured workspace binding when required;
6. admit the task through existing authorization;
7. create or invoke the existing durable integrated run path;
8. print stable content-free task/run identity and terminal status;
9. never bypass model/tool/workspace authorization.

### Task status

`phoenix task status` exposes bounded content-free state only.

It may include:

- task ID;
- run ID;
- configured profile name;
- provider ID;
- Phoenix model ID;
- run state;
- current step category;
- model turns used and maximum;
- tool calls used and maximum;
- accepted/rejected tool-proposal counts;
- deadline remaining or expired;
- cancellation state;
- provider-failure category;
- durable recovery disposition;
- terminal category.

It must not expose prompt text, response text, tool arguments, tool results, workspace bytes,
memory content, credentials, approvals, or raw provider payloads.

### Unknown telemetry

Context and token accounting are not always exact across providers.

Phoenix must never fabricate precision.

Any context, token, or usage field must explicitly represent one of:

- exact;
- provider-reported;
- estimated by an explicitly documented deterministic rule; or
- unknown.

An unknown value is preferable to an invented remaining-context number.

## Operator configuration

### Configuration location

The implementation must support an explicit `--config` path supplied by the operator.

A platform-local default location may also exist, but the effective source and provenance must be
observable through `phoenix config show` without revealing secrets.

### Format

The initial document should use a standard-library-readable bounded format. TOML is preferred on
Python 3.12 because `tomllib` avoids a required runtime dependency.

The document is declarative and finite.

A representative shape is:

```toml
schema_version = 1

[providers.ollama-local]
kind = "ollama-local"

[models.dev]
provider = "ollama-local"
provider_model_name = "qwen3:4b-instruct"
# expected_digest may be configured when immutable revision evidence is required.

[workspaces.project]
kind = "development-checkout"
root = "C:/Projects/example"

[profiles.development]
model = "dev"
workspace = "project"
allow_workspace_patch = true
```

The example is descriptive. The implementation must preserve existing typed contracts and may
normalize field names during the Proposed-to-Accepted review.

### Configuration security

The configuration loader must:

- reject unknown schema versions;
- reject unknown fields unless explicitly versioned for forward compatibility;
- reject duplicate normalized identifiers;
- reject unbounded text or collection sizes;
- reject invalid provider/model/profile/workspace references;
- reject model-controlled endpoint overrides;
- reject credentials in fields intended only for secret references;
- retain source/provenance information;
- fail before provider or tool execution when invalid.

`phoenix config init` may create a minimal commented scaffold only when the destination does not
already exist. It must not discover and authorize local models automatically.

`phoenix config show` must be redacted and content-free with respect to secrets.

## Doctor

`phoenix doctor` is a read-only operational diagnostic.

It evaluates current configuration and environment without widening authority or mutating external
systems.

For each configured component, the result should use stable categories such as:

```text
package              ready
configuration        ready | invalid | absent
provider              reachable | unreachable | timeout | invalid
model                 available | unavailable | revision_mismatch | unknown
profile               ready | invalid
workspace             ready | unavailable | unsafe | invalid
memory                ready | disabled | invalid
network               ready | disabled | invalid
browser               ready | disabled | unconfigured | invalid
host                  ready | disabled | unconfigured | invalid
```

For Ollama, `doctor` may perform the same bounded reviewed loopback diagnostic already defined by
RFC-0038. It must not start Ollama, pull a model, change a model, or authorize a discovered model.

Diagnostics must explain the operator action category where safe, for example:

```text
provider ollama-local: unreachable
operator_action: start the configured local provider and retry doctor
```

The diagnostic must not print secrets, raw provider responses, raw stack traces, or model content.

## Registered development checkout

A development checkout is new opt-in authority and therefore requires an explicit boundary.

### Registration

The operator configuration binds a stable workspace name to one absolute native root.

The root is consumed only by trusted composition. It is never copied into model context, tool
arguments, normal logs, or audit events.

The model operates on logical paths such as:

```text
src/example.py
```

not:

```text
C:\Projects\example\src\example.py
```

### Root admission

Before a development checkout becomes usable, Phoenix must verify at minimum:

- root exists;
- root is a directory;
- root is absolute and canonical for the platform;
- root is not a filesystem/device root;
- root is not itself a symlink, junction, reparse point, or other special object;
- configured root identity can be revalidated before mutation;
- the adapter can prevent escape through descendants.

A failed admission does not partially enable the workspace.

## `workspace.patch`

### Authority

`workspace.patch` is a new exact protected action.

It is independent from:

- `workspace.read`;
- `workspace.write`;
- `workspace.import`;
- `workspace.export`;
- `tool.invoke`;
- `agent.run`;
- `model.infer`.

Normal agent use still requires the surrounding RFC-0027/RFC-0036 tool authorization path. The
existence of a registered checkout does not grant `workspace.patch` to any profile.

The initial development profile may expose the patch tool only when trusted configuration and
current policy both enable it.

### Initial mutation scope

v0.39 `workspace.patch` supports only mutation of an existing regular UTF-8 text file beneath one
registered development checkout.

The initial version does not create, delete, rename, move, chmod, execute, compile, or otherwise
operate on files.

### Patch request

A patch request must bind at least:

- workspace identity;
- canonical logical path;
- expected complete base digest;
- bounded ordered text edits;
- task/run identity;
- tool invocation identity.

Each text edit must include enough expected old-text evidence to reject an edit that no longer
matches the exact admitted base.

Edits must be sorted, non-overlapping, deterministic, and bounded.

Phoenix must not execute arbitrary patch-language directives, shell fragments, Git commands, or
filesystem commands embedded in patch text.

### Bounds

The implementation must define constants no weaker than these initial upper bounds:

- target file bytes: at most 1 MiB;
- patch request bytes: at most 256 KiB;
- edit count: at most 64;
- total replacement text: at most 256 KiB;
- total affected lines: at most 2,000;
- one target file per `workspace.patch` invocation.

A later RFC may revise these after dogfood.

### Path safety

Before preparation and again before commit, Phoenix must reject:

- `..` traversal;
- absolute, drive-relative, UNC, device, or alternate-data-stream paths;
- separator or Unicode aliases that escape canonical logical-path rules;
- symlink components;
- junction or reparse-point components;
- hardlinked target files where unique-file identity cannot be established safely;
- FIFOs, sockets, devices, or other special objects;
- a target whose resolved identity escapes the registered root;
- a root whose identity changed since admission.

Path checking must be handle/identity-aware where the platform exposes the required primitives. A
string-prefix comparison alone is insufficient.

### Stale-base protection

The complete current target digest must equal the request's expected base digest.

If the file changed after the model read it, preparation fails with a stable stale-base category.
Phoenix does not silently rebase, regenerate, merge, or retry the patch.

### Preparation

Patch preparation is zero-effect.

It must:

1. revalidate current authority;
2. revalidate workspace registration and root identity;
3. resolve the logical target safely;
4. verify regular-text-file constraints;
5. verify target size and UTF-8 decoding;
6. verify expected base digest;
7. verify every expected text edit;
8. construct the candidate bytes in memory;
9. enforce post-patch size bounds;
10. compute before digest, after digest, and patch digest;
11. create a bounded `WorkspacePatchPreparation` identity;
12. produce trusted review metadata/diff.

Preparation never modifies the target.

### Review and approval

When current policy/profile requires human approval, approval must bind to the exact prepared patch
identity and digest.

The trusted renderer may show the operator the logical path and complete bounded unified diff.

The diff is for review, not authority. Text inside the diff cannot modify policy, approval scope,
workspace selection, or tool selection.

If a diff would exceed the reviewed display bound, the patch must be rejected rather than silently
truncated for approval.

### Commit

Patch commit is the external effect.

Immediately before mutation Phoenix must revalidate:

- current policy;
- current task/run/profile/tool identity;
- approval validity when required;
- workspace registration;
- root identity;
- target path identity;
- target regular-file status;
- complete current base digest;
- prepared patch digest;
- deadline and cancellation state.

The write must use a same-directory confined temporary file or an equivalent platform-safe atomic
replacement sequence.

The temporary file must not be model-named.

If final atomic replacement cannot be proven safe on the platform/adapter, the operation fails
closed.

### Result

A successful result may expose to the calling task:

- workspace identity;
- logical path;
- before digest;
- after digest;
- changed-line count;
- patch preparation ID;
- terminal mutation status.

Normal audit/log/metric evidence remains content-free and must not persist source text or diff
content.

## Review/diff surface

The operator task interface must make successful mutation understandable.

A terminal task summary may render:

```text
files_changed: 1
path: src/example.py
before_digest: ...
after_digest: ...
review_status: approved
```

The interactive CLI may additionally display the bounded trusted diff while the task is active.

Git is not required for this review. v0.39 does not need `git status`, `git diff`, or any Git
mutation authority.

## Task and budget observability

The operator should be able to answer:

- what task is running;
- what profile is active;
- what configured model is active;
- whether the provider is healthy;
- how many model turns remain;
- how many tool calls remain;
- whether a deadline is near or expired;
- why the loop stopped;
- whether recovery or cancellation is pending.

Phoenix should expose these facts through immutable content-free snapshots owned by the existing
runtime services.

This RFC does not introduce automatic context summarization, compression, retrieval policy, or
model routing. Visibility comes before new context automation.

## Failure model

Stable public/operator failure categories should include at least:

- configuration_absent;
- configuration_invalid;
- provider_unreachable;
- provider_timeout;
- configured_model_unavailable;
- model_revision_mismatch;
- profile_invalid;
- workspace_unavailable;
- workspace_unsafe;
- workspace_patch_unauthorized;
- workspace_patch_stale_base;
- workspace_patch_path_escape;
- workspace_patch_special_file;
- workspace_patch_binary_or_invalid_text;
- workspace_patch_limit_exceeded;
- workspace_patch_approval_required;
- workspace_patch_approval_invalid;
- workspace_patch_commit_indeterminate;
- task_cancelled;
- task_deadline_exceeded;
- task_budget_exhausted;
- durable_recovery_required;
- durable_recovery_rejected.

Failures must remain safe and content-free by default.

## Indeterminate patch effects

A patch attempt may become externally uncertain if a process crashes during final replacement and
the adapter cannot prove whether the candidate became authoritative.

RFC-0037 rules apply.

Phoenix must not blindly replay the patch.

Recovery must re-read the target and classify it by trusted evidence such as:

- still equal to before digest;
- exactly equal to after digest;
- equal to neither digest;
- target missing or unsafe;
- root identity changed.

Only a proven pre-effect state may admit a fresh new patch attempt. A proven after-state is treated
as already applied. Unknown state requires operator reconciliation.

## Security invariants

1. The CLI grants no authority beyond the services it invokes.
2. Task text is untrusted data and cannot configure authority.
3. Provider/model discovery is never authorization.
4. Operator configuration is validated before protected execution.
5. Active provider/model/profile/workspace selection is server-owned after configuration admission.
6. Secrets are referenced, not embedded in ordinary config fields.
7. `doctor` is read-only and does not repair, install, start, pull, or authorize anything.
8. A checkout root is trusted configuration, never model-selected.
9. The model sees logical paths, never ambient host-path authority.
10. `workspace.patch` requires fresh exact authority.
11. `workspace.patch` is not equivalent to generic filesystem write.
12. v0.39 patches only one existing bounded UTF-8 regular file per invocation.
13. Every patch requires an expected complete base digest.
14. Stale files are never silently rebased or overwritten.
15. Patch preparation is zero-effect.
16. Approval, when required, binds to the exact prepared patch digest.
17. Commit revalidates path identity, base digest, policy, deadline, cancellation, and approval.
18. Symlink, reparse, hardlink ambiguity, special-file, and root-escape cases fail closed.
19. Successful patch writes are atomic or fail closed.
20. Indeterminate patch effects are never transparently replayed.
21. Audit and normal telemetry persist no file contents or diffs.
22. Workspace content remains untrusted after mutation.
23. No patch automatically triggers shell, tests, Git, network, browser, or desktop actions.
24. Existing behavior is unchanged when operator task/configuration and checkout mutation are omitted.

## Testing strategy

### Deterministic CI

Ordinary CI remains network-free and must cover:

- CLI parsing and safe error behavior;
- config schema validation and provenance;
- unknown/duplicate field rejection;
- doctor result normalization with deterministic provider fixtures;
- task composition without provider-specific bypass;
- status snapshot bounds and redaction;
- checkout root admission fixtures;
- path traversal and alias rejection;
- symlink/junction/reparse/hardlink/special-file rejection where platform fixtures allow;
- stale digest rejection;
- patch edit validation;
- patch bounds;
- approval binding;
- final revalidation;
- cancellation/deadline races;
- simulated indeterminate commit recovery;
- no raw content in logs/audit/metrics;
- compatibility when the new configuration is omitted.

### Real-provider dogfood

Real-provider dogfood remains separately invoked and must not become an ordinary CI dependency.

The v0.39 dogfood uses an official candidate wheel installed into a clean virtual environment.

The decisive rule is:

> **No custom Python composition helper may be used to satisfy the normal-path dogfood gate.**

The official product path must be sufficient.

At minimum the manual dogfood must demonstrate:

1. install candidate wheel with no source-tree import;
2. `phoenix config validate` succeeds for an explicit reviewed local provider/model/profile;
3. with Ollama stopped, `phoenix doctor` reports `provider_unreachable` without mutation;
4. operator starts Ollama manually;
5. `phoenix doctor` reports the configured model as available;
6. `phoenix task run` starts a real-model task through the normal integrated path;
7. the task reads admitted workspace context;
8. the model proposes a bounded patch;
9. Phoenix renders the trusted diff;
10. required approval binds to that exact patch;
11. Phoenix applies the patch and reports before/after digests;
12. a stale-base patch is rejected;
13. a traversal/reparse/special-file attempt is rejected;
14. provider interruption produces controlled failure;
15. stop/restart plus `phoenix task resume` follows RFC-0037 live revalidation;
16. task status reports finite budgets and terminal reason;
17. no shell or Git authority is used;
18. normal evidence remains content-free.

The release candidate should exercise 10-20 normal tasks across more than one task shape before
v0.39.0 is accepted for publication.

## Release gate

The final v0.39 release gate must include:

- full repository quality gate;
- selected RFC-0038 regression suites;
- RFC-0039 deterministic CLI/config/doctor/task tests;
- RFC-0039 workspace patch security/adversarial matrix;
- RFC-0037 recovery regression for patch indeterminate effects;
- package build and structural inspection;
- wheel rebuild from validated sdist;
- isolated offline install of original and rebuilt wheels;
- packaged `phoenix --help`, `phoenix config --help`, `phoenix doctor --help`, and
  `phoenix task --help` smoke tests without source imports;
- explicit separately invoked real-provider dogfood checklist;
- proof that the normal-path dogfood did not use a custom Python composition helper.

Ordinary package import and deterministic CI must continue to require no provider, model, network,
or credentials.

## Compatibility

- Existing `phoenix authority` behavior remains supported.
- Existing Python inference and agent composition APIs remain supported unless a separately reviewed
  compatibility change is required.
- Existing provider-neutral behavior remains the default when real-provider configuration is absent.
- RFC-0031 workspaces remain unchanged when no development checkout adapter is configured.
- No model, provider, workspace, tool, or patch authority is enabled by package installation alone.
- v0.38 durable state must not be silently reinterpreted as new `workspace.patch` authority.

## Migration

No automatic migration grants new authority.

An operator who wants the v0.39 normal task path must explicitly create/validate configuration.

An operator who wants checkout mutation must additionally:

1. register the checkout root;
2. enable the development profile's patch tool;
3. grant current policy authority for the exact action/resource;
4. satisfy approval requirements when configured.

Existing v0.38 installations without these additions retain their prior behavior.

## Deferred work

The following are intentionally deferred until v0.39 dogfood provides evidence:

- bounded command execution;
- test-command profiles;
- Git read-only helpers;
- Git local staging/commit;
- remote Git push;
- richer desktop workflows;
- a second production provider;
- model selection/routing;
- hosted-provider credential UX;
- automatic context compression/summarization;
- connector ecosystem expansion;
- general file create/delete/rename operations.

The expected next authority progression, if v0.39 succeeds, is:

```text
workspace.patch
    ↓
bounded command execution
    ↓
controlled local Git
    ↓
approved remote Git
```

Each step requires separate evidence and review.

## Acceptance criteria

RFC-0039 may move from Proposed to Accepted only when the implementation and evidence demonstrate
all of the following:

- the official package exposes normal config/doctor/task entrypoints;
- no custom composition helper is needed for the normal task path;
- provider/model discovery remains non-authoritative;
- a real configured model runs through RFC-0026/RFC-0027/RFC-0036;
- task state and budgets are observable without leaking content;
- checkout roots are explicit and fail closed against path escapes;
- `workspace.patch` cannot mutate outside its registered root;
- stale-base, binary, special-file, reparse, and oversized cases fail closed;
- review/approval binds to the exact prepared patch;
- commit revalidation prevents stale authorization or stale file replacement;
- indeterminate patch effects are not replayed blindly;
- logs/audit/metrics remain content-free;
- ordinary CI remains deterministic and network-free;
- real-provider dogfood completes through the official wheel and official entrypoint.

The product-level success criterion is intentionally simple:

```text
install official Phoenix wheel
        ↓
validate explicit configuration
        ↓
doctor explains readiness
        ↓
start task through phoenix task
        ↓
real model uses existing Phoenix authority
        ↓
read admitted workspace context
        ↓
prepare bounded workspace.patch
        ↓
review / approve
        ↓
commit safely
        ↓
show result and finite task status
```

with **no task-specific helper script**.
