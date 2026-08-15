# RFC-0032: Secure Host Automation and Desktop Control

- Status: Draft
- Target release: Phoenix OS v0.32.0
- Owners: Phoenix OS maintainers
- Depends on: RFC-0002, RFC-0003, RFC-0004, RFC-0005, RFC-0006, RFC-0008, RFC-0009, RFC-0010, RFC-0012, RFC-0027, RFC-0028, and RFC-0031

## Summary

RFC-0032 defines an optional, bounded, policy-controlled host-automation boundary for
Phoenix OS.

The public contracts are operating-system-neutral. Phoenix models host processes,
windows, configured applications, and text clipboard access through Phoenix-owned
identities and immutable bounded requests/results. Concrete operating-system behavior
lives behind a `HostAutomationAdapter`.

Phoenix OS v0.32.0 implements only a Windows adapter. Linux and macOS adapters are not
required by this release, and Windows-specific handles, structures, error objects,
paths, process objects, clipboard handles, or SDK types never enter the public
contracts.

Host automation is disabled by default. Omitting host-automation configuration
preserves Phoenix OS v0.31.0 behavior and creates no adapter, process, window,
clipboard, worker, operating-system handle, or additional authority.

Model output, process metadata, window metadata, window titles, application metadata,
clipboard text, tool output, and adapter responses are data, never authority. A model
may propose a host action, but only trusted Phoenix configuration, current policy,
and required approval may admit the exact effect.

## Principle

> **Desktop state is data; host effects require fresh authority.**

Observing a process, window, configured application, or clipboard value never grants
permission to focus, launch, close, read, write, execute, kill, type, click, elevate,
or perform any other host action.

## Goals

- Optional host automation disabled by default
- Operating-system-neutral Phoenix public contracts
- Windows as the only concrete v0.32.0 implementation target
- Server-owned stable host and configured-application identities
- Opaque bounded process/window identities that never expose native handles as authority
- Fresh exact `host.*` authorization for every host operation
- Independent agent-tool authorization and host-operation authorization
- Action-bound approval for destructive or configured-sensitive host effects
- Read-only bounded process and window discovery
- Launch of explicitly configured applications without arbitrary command execution
- Exact stale-safe window focus
- Graceful configured application close without force-kill semantics
- Explicit bounded text clipboard write
- Separately authorized, separately configurable bounded text clipboard read
- No transparent retry of host side effects
- Fail-closed stale-identity and desktop-state validation
- Content-free operational observability and safe public failures
- Runtime-owned finite adapter lifecycle
- Compatibility with Phoenix OS v0.31.0 by omission

## Non-goals

- Arbitrary shell execution
- Arbitrary PowerShell execution
- Generic command-line execution
- Model-selected executable paths
- Model-selected working directories or environment variables
- Arbitrary process termination or `process.kill`
- Privilege elevation, UAC bypass, administrator automation, or `admin.*`
- Raw keyboard injection
- Raw mouse injection
- Screen-coordinate automation
- Arbitrary UI Automation trees or accessibility-tree scripting
- Browser automation
- Screenshot capture, OCR, vision-based clicking, or screen scraping
- Arbitrary host-filesystem access
- Automatically opening workspace artifacts as native files
- Installing, downloading, updating, or discovering executable software
- Remote-desktop or remote-host control
- Linux implementation in v0.32.0
- macOS implementation in v0.32.0
- Treating installed application metadata as trusted instructions
- Treating clipboard content as a secret-management replacement
- Guaranteeing exactly-once external operating-system effects
- A hostile-code sandbox for installed host adapters

## Terminology

- **Host:** one server-owned operating-system execution target configured by Phoenix.
- **Host ID:** stable Phoenix-owned identity for one configured host target.
- **Host automation adapter:** provider-neutral boundary implementing reviewed host operations.
- **Windows host adapter:** the only concrete v0.32.0 host automation implementation.
- **Configured application:** one server-owned launch profile identified by Phoenix, not by model-provided executable path.
- **Application ID:** stable Phoenix-owned identity for one configured application profile.
- **Process ID:** opaque Phoenix host-process identity; not a native PID contract and not authority.
- **Window ID:** opaque Phoenix host-window identity; not a native window handle contract and not authority.
- **Host epoch:** finite adapter-session identity used to reject stale process/window references after adapter restart or re-enumeration boundaries.
- **Host effect:** an operation that changes operating-system-visible state.
- **Sensitive host data:** data such as clipboard text or window titles that may contain private or secret material and must never enter routine operational telemetry.

## Architecture

The intended boundary is:

```text
Agent / caller
    |
    +-- Agent Tool boundary when model-originated
    |      |
    |      +-- tool.invoke authorization
    |      +-- tool approval when required
    |
    +-- HostAutomationService
           |
           +-- fresh exact host.* authorization
           +-- host-specific validation and approval requirements
           |
           +-- HostAutomationAdapter
                  |
                  +-- WindowsHostAutomationAdapter   (v0.32.0)
                         |
                         +-- reviewed Win32/process/clipboard APIs
```

The model never receives the adapter, native handles, executable callbacks, operating-
system objects, policy objects, approval objects, or credentials.

Agent tools do not call Win32 directly. They translate validated tool arguments into
Phoenix host-automation requests and call the host service. A model-originated host
effect therefore requires the normal RFC-0027 `tool.invoke` decision and the exact
RFC-0032 `host.*` decision. Neither authorization implies the other.

## Threat model

The subsystem treats model proposals, process names, application names, window titles,
window metadata, clipboard content, adapter-returned metadata, native operating-system
state, persisted configuration metadata, and tool results as untrusted data.

The implementation must address confused-deputy authorization, arbitrary executable
selection, shell/command-line smuggling, stale PID/window-handle reuse, process/window
identity substitution, focus TOCTOU, close-the-wrong-window races, process exit races,
application relaunch duplication, clipboard secret disclosure, clipboard prompt
injection, oversized clipboard payloads, Unicode edge cases, hidden or system windows,
session/desktop changes, privilege-boundary confusion, adapter exception leakage,
cancellation after effect admission, duplicate effects after restart, unbounded
enumeration, raw host metadata in logs, and model attempts to turn observed desktop
state into authority.

Windows native APIs and installed host adapters are trusted implementation code, but
all model-controlled input and all native host state received by those adapters remain
untrusted until validated through Phoenix-owned contracts.

## Security invariants

1. Host automation is disabled unless explicitly configured.
2. Enabling host automation creates no permission, approval, application launch, process, window action, clipboard disclosure, clipboard mutation, shell, keyboard, mouse, filesystem, network, or administrator authority automatically.
3. Public host-automation contracts are operating-system-neutral.
4. Windows is the only required concrete adapter for Phoenix OS v0.32.0.
5. No Win32 handle, PID contract, HWND contract, COM object, native structure, process object, clipboard handle, OS error object, or Windows SDK type appears in public Phoenix contracts.
6. Every configured host has a stable server-owned `HostId`.
7. Every launchable application profile has a stable server-owned `HostApplicationId`.
8. A model cannot select an arbitrary executable path, command line, working directory, environment block, shell verb, elevation verb, package identifier, or native launcher.
9. Process and window identities exposed by Phoenix are opaque data and do not grant authority.
10. Native process IDs and window handles are implementation details and are revalidated by the adapter before sensitive operations.
11. Every `host.process.list` operation requires fresh exact authorization.
12. Every `host.window.list` operation requires fresh exact authorization.
13. Every `host.app.launch` operation requires fresh exact authorization.
14. Every `host.window.focus` operation requires fresh exact authorization.
15. Every `host.app.close` operation requires fresh exact authorization.
16. Every `host.clipboard.write` operation requires fresh exact authorization.
17. Every `host.clipboard.read` operation requires fresh exact authorization.
18. Authorization for `agent.run`, `model.infer`, `tool.invoke`, `workspace.*`, `memory.*`, or any other Phoenix action does not imply any `host.*` action.
19. Authorization for one `host.*` action never implies another `host.*` action.
20. Current policy always wins over prior enumeration results, previous approvals, model output, persisted metadata, or adapter state.
21. Model-provided strings are never interpreted directly as policy resource identifiers.
22. Model output cannot create, widen, replace, or mutate a configured host or application profile.
23. Model output cannot grant itself access to another desktop session, user session, integrity level, or host target.
24. Listing processes grants no right to launch, focus, close, kill, inspect command lines, read process memory, or access files.
25. Process enumeration is strictly bounded and excludes raw command lines, environment blocks, process memory, open handles, access tokens, and unrestricted executable paths from the initial public result.
26. Listing windows grants no right to focus, close, type into, click, inspect controls, capture pixels, or access the owning process.
27. Window enumeration is strictly bounded and exposes only reviewed Phoenix-owned metadata required by the host-control surface.
28. Window titles and other user-visible labels are untrusted potentially sensitive data and never appear in routine logs, metrics, health, audit payload text, or public error bodies.
29. A `HostWindowId` is bound to one configured host and finite host epoch.
30. Focus fails closed when the target window identity is stale, no longer belongs to the expected process/application relation, is unavailable, or cannot be revalidated immediately before the effect.
31. Focus does not authorize keyboard or mouse injection.
32. Application launch resolves only a trusted server-owned `HostApplicationId` through configured adapter data.
33. The initial launch surface accepts no arbitrary model-controlled command line, shell syntax, executable path, working directory, environment mutation, or elevation request.
34. A successful launch result is descriptive data and grants no subsequent process/window authority.
35. Launch is an external side effect and is never transparently retried.
36. If Phoenix loses certainty after launch admission, recovery treats the outcome as indeterminate rather than automatically launching again.
37. `host.app.close` is graceful-close semantics only in v0.32.0; force kill is not included.
38. Close targets one exact revalidated application/process identity and cannot become `process.kill` through arguments.
39. Destructive close requires action-bound approval whenever the configured policy/tool descriptor marks it approval-required; model text cannot create or satisfy that approval.
40. Altering the host, application/process identity, operation, or normalized arguments invalidates a previously obtained approval.
41. Host side effects are not transparently retried by the host service or Windows adapter.
42. Cancellation prevents new effects; cancellation after an operating-system effect has started never fabricates a guaranteed rollback.
43. Durable agent recovery never transparently replays an indeterminate host side effect.
44. Clipboard support in v0.32.0 is text-only and strictly bounded by configured character/byte limits.
45. Clipboard file lists, images, HTML, rich-text payloads, arbitrary binary formats, and executable objects are not part of the initial public surface.
46. `host.clipboard.read` is separately configurable from clipboard write and is disabled unless explicitly enabled.
47. Clipboard read results are sensitive untrusted data and never appear in routine operational telemetry or public error text.
48. Clipboard text cannot grant permissions, approvals, credentials, tool authority, workspace authority, host authority, or system-message status.
49. Clipboard write accepts bounded validated text only and does not imply clipboard read authority.
50. Shell, PowerShell, keyboard, mouse, force-kill, privilege elevation, and administrator actions are outside the v0.32.0 authority surface.
51. Adapter operations have finite deadlines, bounded outputs, bounded enumeration counts, and deterministic cancellation behavior.
52. Adapter exceptions and native error details are translated into safe Phoenix-owned failures.
53. Operational observability is content-free and may record only reviewed identifiers, counts, action names, outcome codes, durations, and bounded non-sensitive metadata.
54. Runtime owns adapter startup, availability, cancellation boundaries, and reverse-order shutdown.
55. Unsupported platforms fail explicitly when host automation is configured; omission remains a no-op.
56. Existing Phoenix OS v0.31.0 behavior remains unchanged when host automation configuration is absent.

## Initial action surface

The initial v0.32.0 action names are:

```text
host.process.list
host.window.list
host.app.launch
host.window.focus
host.app.close
host.clipboard.write
host.clipboard.read
```

The action set is intentionally narrow. `shell.*`, `powershell.*`, `keyboard.*`,
`mouse.*`, `process.kill`, and `admin.*` are not aliases, hidden modes, or argument
variants of the initial actions.

## Authorization resources

Every host resource begins with one exact server-owned host identity:

```text
host-automation:host:<host-id>
```

Initial collection resources are:

```text
host-automation:host:<host-id>/processes
host-automation:host:<host-id>/windows
host-automation:host:<host-id>/clipboard:text
```

Configured applications use:

```text
host-automation:host:<host-id>/application:<application-id>
```

Runtime-discovered process and window resources use opaque Phoenix identities:

```text
host-automation:host:<host-id>/process:<process-id>
host-automation:host:<host-id>/window:<window-id>
```

Native PIDs, HWND values, executable paths, window titles, command lines, clipboard
contents, and model-provided strings are never policy resource names.

## Proposed contracts

- `HostId`
- `HostEpoch`
- `HostApplicationId`
- `HostProcessId`
- `HostWindowId`
- `HostProcessDescriptor`
- `HostWindowDescriptor`
- `HostProcessListRequest`
- `HostProcessListResult`
- `HostWindowListRequest`
- `HostWindowListResult`
- `HostApplicationLaunchRequest`
- `HostApplicationLaunchResult`
- `HostWindowFocusRequest`
- `HostWindowFocusResult`
- `HostApplicationCloseRequest`
- `HostApplicationCloseResult`
- `HostClipboardReadRequest`
- `HostClipboardReadResult`
- `HostClipboardWriteRequest`
- `HostClipboardWriteResult`
- `HostAutomationLimits`
- `HostAutomationAdapter`
- `HostAutomationAuthorizer`
- `HostAutomationApprovalGate`
- `HostAutomationService`
- `HostAutomationObserver`
- `HostAutomationAdministration`
- `HostAutomationError`
- `WindowsHostAutomationAdapter`

All public contracts are immutable and bounded and contain no callback, executable
object, native handle, raw PID/HWND authority, open process handle, clipboard handle,
provider SDK object, shell command, credential, secret value, or arbitrary native
path authority.

## Configured applications

Phoenix application launch is profile-based, not path-based.

Trusted configuration maps one `HostApplicationId` to adapter-owned Windows launch
configuration. The public request names only the configured application identity and
bounded Phoenix-owned request metadata. The model cannot replace the executable,
working directory, shell verb, environment, elevation behavior, or adapter.

The initial release does not require arbitrary launch arguments. If later slices add
arguments, they must use an explicit bounded per-application schema and cannot expose
a generic command-line escape hatch.

## Process and window discovery

Process/window discovery exists to support controlled host actions, not unrestricted
host inspection.

Enumeration is bounded by configured result limits and deadlines. Results are sorted
or normalized deterministically where practical and carry Phoenix-owned identities.
Native identities remain inside the adapter and are paired with a finite host epoch so
stale identities fail closed after adapter restart or identity invalidation.

Process results do not expose command lines, environment variables, process memory,
security tokens, handles, or unrestricted paths. Window results expose only reviewed
metadata required for selection and may carry bounded user-visible labels as sensitive
untrusted data.

## Window focus and UI TOCTOU

Focus is intentionally narrower than generic desktop input.

The adapter revalidates the target immediately before attempting focus. A stale or
reused native handle, changed owning process, changed host epoch, vanished window, or
unsupported desktop/session boundary causes failure rather than retargeting.

Phoenix does not infer that a focused window remains focused after the operation. A
successful focus is only evidence that the adapter admitted and attempted the exact
reviewed operation at that time; it is not authority for later keyboard/mouse work.

Raw keyboard and mouse injection are deferred because focus can change between
observation and input, making UI-target TOCTOU materially broader than the bounded
v0.32.0 action set.

## Application close and destructive effects

`host.app.close` requests a graceful close of one exact revalidated configured
application/process instance. It does not terminate arbitrary processes and does not
escalate to force-kill when graceful close fails.

Close may cause unsaved user data loss. Agent-facing close tools therefore declare a
destructive effect classification and participate in RFC-0027 action-bound approval.
The host service also supports an explicit approval gate so non-agent callers cannot
bypass configured close confirmation merely by avoiding the agent tool layer.

## Clipboard boundary

Clipboard support is text-only in the initial release.

`host.clipboard.write` and `host.clipboard.read` are distinct permissions. Deployments
may enable write while leaving read disabled. Clipboard read is treated as a sensitive
data disclosure because clipboard text commonly contains passwords, tokens, private
messages, source code, and other confidential material.

Clipboard contents returned to an agent remain untrusted data. They cannot become a
system instruction or grant any Phoenix authority merely because they came from the
local desktop.

The adapter never logs clipboard text and public failures never include clipboard
contents.

## Agent tool integration

RFC-0032 does not let a model invoke the host adapter directly.

Reviewed Phoenix tools translate strict RFC-0027 tool schemas into exact host requests.
A model-originated action therefore follows:

```text
model proposal
    -> strict tool schema validation
    -> server-owned tool/resource resolution
    -> fresh tool.invoke authorization
    -> action-bound tool approval when required
    -> HostAutomationService
    -> fresh exact host.* authorization
    -> host-specific validation/approval
    -> HostAutomationAdapter
```

Tool results and host results remain untrusted data on subsequent model turns.

## Windows implementation boundary

`WindowsHostAutomationAdapter` is the v0.32.0 reference implementation.

It may use reviewed Windows process APIs, window-management APIs, and clipboard APIs
internally. Native identifiers and errors are translated at the adapter boundary.

The adapter must avoid shell interpretation for application launch, avoid arbitrary
command strings, reject unsupported elevation, bound all enumeration and text
materialization, and fail closed on unsafe session/desktop or identity conditions.

Linux and macOS adapters may be added by future RFCs or later implementations without
changing the public host contracts when semantics are equivalent. v0.32.0 acceptance
does not require those adapters.

## Observability and safe failures

Host automation events and administration are content-free.

Operational surfaces may expose host/application/process/window Phoenix IDs, action
names, bounded counts, configured effect classification, durations, availability, and
safe reason codes. They do not expose window-title text, clipboard text, executable
paths, command lines, environment variables, native handles, raw OS errors, approval
evidence, secrets, or credentials.

## Runtime lifecycle

Host automation composition is explicit and opt-in.

When configured, Runtime owns the host service, adapter, bounded workers if any,
deadlines, cancellation, and reverse-order shutdown. No adapter or OS handle is
created merely by importing the package or constructing an unrelated agent runtime.

On unsupported operating systems, explicit Windows-adapter configuration fails with a
safe unsupported-platform error. Omitting host automation remains compatible and does
not probe the desktop.

## Compatibility

When host-automation configuration is omitted, Phoenix creates no host service,
Windows adapter, process/window enumeration, clipboard access, launch profile,
background worker, or host tool automatically.

Existing Phoenix OS v0.31.0 inference, agent, durable-agent, multi-agent, memory, and
workspace behavior remains unchanged.

## Slice plan

### Slice 0 - RFC foundation and executable specification

- [x] Draft RFC-0032 with OS-neutral contracts and Windows-only v0.32.0 target
- [x] Define initial `host.*` action and resource naming
- [x] Define no-shell/no-keyboard/no-mouse/no-force-kill authority boundary
- [x] Define independent tool and host authorization
- [x] Define compatibility-by-omission contract
- [ ] Add RFC structure and regression tests

### Slice 1 - Core contracts, identities, authorization, and fake adapter

- [ ] Immutable bounded host/application/process/window contracts
- [ ] Host epoch and stale-identity rules
- [ ] Exact `host.*` constants/resources and current-policy authorization
- [ ] Host automation limits and safe errors
- [ ] Deterministic fake adapter for network/OS-effect-free tests
- [ ] Contract, policy, stale-ID, and compatibility regressions

### Slice 2 - Windows read-only discovery

- [ ] `WindowsHostAutomationAdapter` process enumeration
- [ ] Bounded content-minimized `host.process.list`
- [ ] Bounded reviewed `host.window.list`
- [ ] Native identity translation without public handles
- [ ] Session/desktop and stale-enumeration failure handling
- [ ] Windows discovery integration tests

### Slice 3 - Configured application launch and exact window focus

- [ ] Trusted configured-application registry/profile resolution
- [ ] `host.app.launch` without arbitrary command-line authority
- [ ] `host.window.focus` with immediate identity revalidation
- [ ] Side-effect classification and no-transparent-retry tests
- [ ] Launch-indeterminate and focus-TOCTOU regressions

### Slice 4 - Graceful application close and approval

- [ ] Exact `host.app.close` graceful semantics
- [ ] No force-kill fallback
- [ ] Action-bound destructive approval
- [ ] Changed-target/stale-target approval invalidation
- [ ] Durable indeterminate-effect integration tests

### Slice 5 - Text clipboard boundary

- [ ] Bounded text-only `host.clipboard.write`
- [ ] Separately configurable `host.clipboard.read`
- [ ] Sensitive-data redaction from operational surfaces
- [ ] Clipboard injection and byte/Unicode limit regressions
- [ ] No file/image/HTML/binary clipboard authority

### Slice 6 - Agent integration, observability, administration, and Runtime ownership

- [ ] Reviewed RFC-0027 host tool descriptors and schemas
- [ ] Independent `tool.invoke` plus `host.*` enforcement
- [ ] Content-free host observer events and safe public failures
- [ ] Bounded host administration/health surface
- [ ] Runtime assembler ownership and disabled-by-default tests
- [ ] Windows dogfood host integration

### Slice 7 - Security review, migration, and release hardening

- [ ] Threat-model/security-invariant review
- [ ] ADRs for host authority, application profiles, native identity opacity, and UI TOCTOU
- [ ] v0.31.0 to v0.32.0 migration guidance
- [ ] Named host-automation release gate
- [ ] Windows dogfood with real process/window/app/clipboard effects
- [ ] Offline wheel/sdist validation
- [ ] Release notes and package version 0.32.0
- [ ] Tag, artifacts, and checksums

## Acceptance

RFC-0032 is complete when host automation is opt-in and bounded, public contracts are
OS-neutral, Windows is the reviewed v0.32.0 implementation, arbitrary executable and
shell authority cannot enter through model arguments, every operation has fresh exact
`host.*` authorization, model-originated effects also retain independent RFC-0027 tool
authorization, process/window identities fail closed when stale, launch does not gain
arbitrary command-line authority, focus does not imply keyboard/mouse authority,
application close is graceful and approval-bound when destructive, clipboard read and
write are independently authorized and text-only, sensitive desktop data is absent
from operational telemetry, host side effects are never transparently replayed after
indeterminate failure, Runtime owns finite lifecycle, unsupported platforms fail
safely when explicitly configured, and omitting host automation preserves Phoenix OS
v0.31.0 behavior.
