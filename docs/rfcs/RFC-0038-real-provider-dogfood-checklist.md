# RFC-0038 Real-Provider Dogfood Checklist

This is the separately invoked operational checklist for RFC-0038 real-provider
dogfood. It is not a normal CI test and it must not be called by the default test
or release-test path.

## Safety and authority rules

- Use only the reviewed loopback-local Ollama provider configuration.
- Do not automatically install, start, stop, upgrade, pull, create, push, or delete
  Ollama models.
- Do not add provider/model discovery results to Phoenix authority automatically.
- Real task execution must pass through Phoenix RFC-0026 inference and the normal
  RFC-0027/RFC-0036 execution path. A direct Ollama HTTP call is not task evidence.
- Do not add unrestricted shell, filesystem, HTTP, Git publication, or release
  authority for dogfood.
- Do not enable local-to-cloud fallback.
- Do not retry an inference attempt after provider execution may have started.
- Do not mark a real-dogfood item complete from deterministic fake-provider evidence
  alone.
- Keep package version at `0.37.0` until the final RFC-0038 release slice.

## Content-free evidence

Normal dogfood evidence may record only bounded operational metadata such as:

- provider ID;
- Phoenix model ID;
- configured revision/digest identifier when safe and bounded;
- invocation mode;
- bounded latency/usage counters;
- number of model turns;
- accepted/rejected tool-proposal counts;
- timeout/cancellation/provider-failure category;
- durable recovery disposition;
- terminal task category;
- commit/branch identifier used for the run.

Do not record prompt text, response text, reasoning text, tool arguments, tool
results, browser content, workspace contents, memory contents, clipboard contents,
credentials, approval evidence, raw provider bodies, raw protocol frames, or raw
tracebacks.

## Environment readiness

Run explicitly from the repository root:

```powershell
.\.venv\Scripts\python.exe scripts\check_rfc0038_real_provider_environment.py
```

Exit/status meaning:

- exit `0`, `ready_for_provider_diagnostic`: loopback provider is reachable;
- exit `2`, `provider_unreachable`: no service is reachable on the reviewed endpoint;
- exit `3`, `refused_ci`: the checker detected a CI environment and refused to run.

`ollama_command_present=false` is diagnostic only. The command being absent from
`PATH` does not itself grant or revoke provider authority.

Environment readiness is not real task evidence.

## Required real workload evidence

Do not check these boxes until a real configured local model has executed through
Phoenix.

- [x] Multi-turn development task completed under the bounded development profile.
- [x] Multi-step research task exercised existing browser/network/workspace/memory
      boundaries.
- [x] Controlled desktop/integrated task exercised existing host boundaries.
- [x] At least one malformed or unauthorized tool proposal was rejected.
- [x] Provider/model unavailability produced controlled bounded failure.
- [x] Cancellation during real inference followed bounded cancellation semantics.
- [x] Restart around a model attempt produced controlled recovery evidence.
- [x] An indeterminate model attempt was not silently replayed.
- [x] Current provider/model/profile/tool/schema/policy state was revalidated before
      fresh protected work.
- [x] Model revision drift failed closed when configured immutable evidence was
      available.
- [x] Existing deadline remained continuous across restart.
- [x] Existing budget remained continuous across restart.
- [x] Provider restoration after restart did not automatically resume protected work.
- [x] Content-free evidence was recorded for deliberate failure/restart scenarios.

## Deliberate failure matrix

Operational dogfood should exercise, where practical for the configured local
deployment:

- provider absent at startup;
- provider unavailable before first byte;
- provider unavailable during streaming;
- configured model missing;
- configured revision mismatch;
- malformed/oversized provider output;
- unknown tool;
- invalid tool arguments;
- multiple tool calls;
- ineffective repeated proposals until budget exhaustion;
- cancellation during inference;
- cancellation during a tool call;
- restart before a model attempt;
- restart after a model attempt becomes externally uncertain;
- current-policy/profile/tool/schema changes during downtime;
- deadline expiration while Phoenix is offline;
- nearly exhausted budget across restart.

The expected outcome is controlled failure or recovery evidence, never silent
authority expansion, implicit failover, or silent replay.

## Per-run record template

Record only content-free values:

```text
timestamp_utc:
branch:
commit:
provider_id:
phoenix_model_id:
configured_revision_present:
profile_category:
scenario_category:
model_turn_count:
accepted_tool_proposals:
rejected_tool_proposals:
timeout_count:
cancellation_count:
provider_failure_category:
durable_recovery_disposition:
terminal_category:
contract_violation_observed: yes|no
notes_content_free:
```

A provider outage may be classified as an external outage, but it must not be
converted into a passing Phoenix execution result.
