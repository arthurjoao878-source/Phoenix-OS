# RFC-0032 host-automation threat-model and security-invariant review

- **Reviewed:** 2026-08-18
- **Release candidate:** Phoenix OS v0.32.0
- **Scope:** host identities, application profiles, authorization, agent-tool mediation,
  discovery, native identity opacity, UI TOCTOU, graceful close, approval, clipboard,
  Windows effects, cancellation, durable recovery, observability, administration,
  Runtime ownership, platform handling, and compatibility by omission
- **Result:** Accepted for the v0.32.0 host-automation release-candidate security
  review; publication and the remaining Slice 7 gates remain pending

## Review method

This review maps the RFC-0032 threat model and all fifty-six security invariants to
implementation boundaries and executable regression suites. Desktop state is data;
host effects require fresh authority. Model proposals, process/window metadata,
window titles, clipboard contents, native state, persisted execution metadata, and
tool results remain untrusted data unless a Phoenix-owned boundary validates the exact
operation.

The evidence classes are: explicit opt-in and native opacity; Fresh independent
`host.*` action/resource authorization plus independent RFC-0027 `tool.invoke`;
bounded discovery and stale-safe native revalidation; approval, clipboard, no-retry
and safe observability; and Runtime-owned finite lifecycle with compatibility by
omission.

## Trust boundaries

### Untrusted

Model proposals and tool arguments; process/application labels and window titles;
clipboard text; native PID/HWND, desktop/session state, and native errors; historical
enumeration, approval, and persisted execution metadata; and any data claiming to be
policy, credentials, approval, or a system instruction.

Clipboard text remains sensitive untrusted data, never authority. Window titles and
process metadata are descriptive data, not authorization.

### Trusted but least-authority

Current reviewed Phoenix configuration and Runtime composition; server-owned
`HostId`, `HostApplicationId`, exact `host.*` resources, opaque `HostProcessId` and
`HostWindowId`, finite `HostEpoch`; current authenticated security context and Policy
Engine decisions; configured Windows application profiles; Phoenix approval state;
and reviewed host service, tool adapters, observer, administration projection, and
Windows adapter.

Opaque Phoenix process/window identities are separated from native PID/HWND state.
Neither native identifiers nor observed desktop content become Phoenix authority.

## Threat review

| Threat | Required control | Evidence |
| --- | --- | --- |
| Implicit host authority | Opt-in composition; omission creates no host stack or grant | `test_runtime_assembler.py`, `test_rfc_0032.py` |
| PID/HWND/native leakage | OS-neutral contracts and opaque identities | `test_host_automation_contracts.py`, `test_host_automation_windows.py` |
| Arbitrary executable/command selection | Server-owned `HostApplicationId` profiles, never model-selected executable authority | `test_host_automation_agent_control_tools.py`, `test_host_automation_windows_launch.py` |
| Confused-deputy policy | Fresh independent `host.*` action/resource authorization and independent `tool.invoke` | `test_host_automation_authorization.py`, `test_host_automation_agent_control_tools.py` |
| PID/HWND reuse or stale target | Epoch/creation-time/owner binding and fail-closed revalidation | `test_host_automation_windows_discovery.py`, `test_host_automation_windows_focus.py`, `test_host_automation_windows_close.py` |
| Focus TOCTOU/session change | Immediate pre-effect identity and desktop revalidation | `test_host_automation_windows_focus.py` |
| Wrong/forceful close | Exact process/application binding and graceful `WM_CLOSE` | `test_host_automation_windows_close.py` |
| Forged/replayed close approval | Action-bound, expiring, single-use close approval with exact correlation | `test_host_automation_approval.py`, `test_host_automation_service.py` |
| Duplicate uncertain effect | No transparent retry; post-admission uncertainty is indeterminate | `test_host_automation_windows_launch.py`, `test_host_automation_windows_focus.py`, `test_host_automation_windows_close.py` |
| Durable replay | Started irreversible host work recovers indeterminate for operator review | `test_host_automation_durable_recovery.py` |
| Clipboard disclosure/format expansion | Read disabled by default; distinct authorization; Unicode text only | `test_host_automation_clipboard_hardening.py`, `test_host_automation_windows_clipboard_read.py` |
| Clipboard prompt/authority injection | Clipboard cannot satisfy policy or approval | `test_host_automation_clipboard_hardening.py`, `test_host_automation_agent_control_tools.py` |
| Sensitive telemetry/native errors | Content-free observer/admin and sanitized failures | `test_host_automation_observer.py`, `test_host_automation_administration.py` |
| Late effect after cancellation | Pre-admission prevention; post-admission indeterminate result | `test_host_automation_windows_focus.py`, `test_host_automation_windows_close.py`, `test_runtime_assembler.py` |
| Unsupported platform | Explicit Windows configuration fails before native probe | `test_host_automation_windows.py` |
| Agent bypass | Same host service plus independent tool policy and host approval | `test_host_automation_agent_control_tools.py` |
| Broad shell/input/admin authority | Only seven reviewed actions; strict schemas | `test_rfc_0032.py`, `test_host_automation_agent_control_tools.py` |

## Security-invariant review

### Invariants 1-10: opt-in, OS-neutral contracts, trusted identities, and native opacity

**Result: satisfied.** Host automation is absent unless explicitly composed, and
enabling it creates no policy decision, approval, effect, clipboard, shell, input,
filesystem, network, or administrator authority. Public contracts expose Phoenix
identities rather than PID/HWND/native handles. Windows is the only required v0.32.0
adapter. Hosts and launchable applications use server-owned IDs. Model input cannot
select executable paths, command lines, working directories, environment mutation,
shell/elevation verbs, or native launchers. Native process/window state remains
adapter-private and is revalidated before sensitive effects.

Evidence: `test_host_automation_contracts.py`, `test_host_automation_windows.py`,
`test_host_automation_windows_launch.py`, `test_runtime_assembler.py`,
`test_rfc_0032.py`.

### Invariants 11-24: fresh exact authorization and data never granting authority

**Result: satisfied.** All seven operations use exact `host.*` actions and
server-owned resources with current policy. One host action never implies another.
Agent/model/tool/workspace/memory authority does not imply host authority; model
actions additionally retain independent RFC-0027 `tool.invoke`. Typed resources keep
model strings out of policy resource naming. Model output, prior enumeration,
previous approval, persisted metadata, and observed desktop data cannot create or
widen host/application/session authority.

Evidence: `test_host_automation_authorization.py`,
`test_host_automation_agent_control_tools.py`, `test_host_automation_service.py`,
`test_rfc_0032.py`.

### Invariants 25-36: bounded discovery, stale-safe focus, and non-replayed launch

**Result: satisfied.** Enumeration is finite and content-minimized. Native reuse
produces fresh opaque identities; disappeared targets are removed. Unsafe desktop
state fails safely and titles stay out of routine operational surfaces. Focus binds
host epoch/process/window and rechecks owner, creation time, session, desktop, and
target immediately before one effect admission. Focus grants no keyboard/mouse
authority. Launch resolves only configured server-owned profiles, exposes opaque
descriptive results, and never accepts generic executable/command authority. Failed,
indeterminate, and timed-out admitted launches are not transparently retried.

Evidence: `test_host_automation_windows.py`,
`test_host_automation_windows_discovery.py`, `test_host_automation_windows_focus.py`,
`test_host_automation_windows_launch.py`, `test_host_automation_observer.py`,
`test_host_automation_agent_control_tools.py`.

### Invariants 37-43: graceful close, approval, cancellation, and durable no-replay

**Result: satisfied.** Close targets one exact revalidated application/process and
uses graceful close, never force kill. Host-specific close approval is explicit and
configurable. When required it binds action, host, epoch, application, process,
request, and requester; expires; is single-use; rejects fabricated/tampered evidence;
and is not consumed on failed current policy or target validation. Effects are not
transparently retried. Pre-admission cancellation prevents new effects; after effect
admission uncertainty becomes indeterminate, not fabricated rollback. Durable
recovery does not reissue a started irreversible host effect.

Evidence: `test_host_automation_approval.py`, `test_host_automation_service.py`,
`test_host_automation_windows_close.py`, `test_host_automation_windows_launch.py`,
`test_host_automation_windows_focus.py`, `test_host_automation_durable_recovery.py`,
`test_runtime_assembler.py`.

### Invariants 44-50: text-only clipboard and excluded broad host surfaces

**Result: satisfied.** Clipboard is bounded Unicode text only, with character/UTF-8
limits and no file/image/HTML/Rich Text/binary authority. Windows read is disabled by
default while write remains independent; read/write use distinct permissions.
Clipboard contents stay out of repr/public error chains and content-free operational
telemetry. Malicious clipboard text cannot grant policy, approval, credentials,
tool/workspace/host authority, or system status. Write implies no read authority.
RFC-0032 grants no shell, PowerShell, keyboard, mouse, force-kill, privilege-elevation, or generic administrator authority.

Evidence: `test_host_automation_contracts.py`,
`test_host_automation_authorization.py`,
`test_host_automation_clipboard_hardening.py`,
`test_host_automation_windows_clipboard_read.py`,
`test_host_automation_observer.py`,
`test_host_automation_agent_control_tools.py`, `test_rfc_0032.py`.

### Invariants 51-56: bounded operations, safe failures, observability, Runtime, platform, compatibility

**Result: satisfied.** Limits bound results, text, and deadlines. Native exceptions
and unsafe desktop conditions map to Phoenix-owned failures without native details.
Events, audit/metrics, public errors, and administration/health are content-free
bounded projections. Runtime owns availability and reverse shutdown, drains in-flight
work before adapter close, and fail-closes outside RUNNING. Cancelled shutdown does
not restore authority and remains retryable. Explicit Windows adapter construction on
unsupported platforms fails before native probing. Omission leaves the host stack
absent and preserves v0.31.0 behavior.

Evidence: `test_host_automation_contracts.py`, `test_host_automation_windows.py`,
`test_host_automation_windows_discovery.py`, `test_host_automation_windows_focus.py`,
`test_host_automation_windows_launch.py`, `test_host_automation_windows_close.py`,
`test_host_automation_observer.py`, `test_host_automation_administration.py`,
`test_runtime_assembler.py`, `test_rfc_0032.py`.

## Residual risks

- Trusted deployment components can misuse authority explicitly granted to them; OS
  isolation and endpoint permissions remain deployment responsibilities.
- Window titles and clipboard text can influence a model as untrusted data even though
  they cannot directly grant Phoenix authority.
- Desktop state can change after effect admission; Phoenix therefore does not promise
  rollback or persistent focus.
- Graceful close can still trigger prompts or unsaved-data loss; approval constrains
  authorization but cannot understand every application's semantic state.
- Clipboard read remains a sensitive disclosure and should be enabled only when
  deployment policy requires it.
- Content-free IDs, counts, outcome codes, availability, durations, and timing may
  reveal traffic patterns.
- The later Slice 7 real-Windows dogfood gate must still exercise actual
  process/window/application/clipboard effects; this review does not replace it.
- Adding shell, PowerShell, keyboard/mouse injection, force kill, elevation, generic
  admin, or arbitrary executable selection requires a separate authority design and
  security review.

## Release conclusion

The RFC-0032 threat model and all fifty-six security invariants are accepted for the
Phoenix OS v0.32.0 host-automation release-candidate security review.

The core boundary remains: Desktop state is data; host effects require fresh
authority. Public identities remain opaque, model-originated effects require
independent tool and host authorization, configured destructive close retains
host-specific approval, sensitive desktop content stays out of operational telemetry,
and uncertain effects are never transparently replayed.

This review does not publish v0.32.0 and does not complete later Slice 7 ADR,
migration, named release-gate, real Windows dogfood, offline package, release-note,
version, tag, artifact, or checksum work.
