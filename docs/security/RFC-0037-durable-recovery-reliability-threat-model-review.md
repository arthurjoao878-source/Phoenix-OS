# RFC-0037 Durable Recovery Reliability Threat-Model and Invariant Review

## Review method

This final S8 release review maps the frozen RFC-0037 threat/failure model and all 48 reliability
invariants to the S1-S8 implementation, deterministic regression surface, and v0.37.0
release boundary.

The dominant rules are:

> Recovery is continuation under fresh evidence, never replay by assumption.

> A restart cannot increase authority, budget, lifetime, or certainty.

> Unknown durable commit outcome is resolved by re-read and exact comparison, never
> blind repetition.

> Fencing generation, not worker belief, decides mutation ownership.

> An external effect with uncertain completion remains indeterminate until reviewed
> evidence proves a safe disposition.

RFC-0028 remains the sole durable-run state machine. RFC-0036 continues to reuse that
primitive for integrated execution. RFC-0037 adds reliability evidence and fail-closed
classification, not a second execution or authority model.

## Trust and failure boundaries

Trusted inputs are Phoenix-owned canonical checkpoint/state-machine rules, current
configuration and dependency identities, current policy/authority, current approval
state, current finite limits/deadlines/cancellation, current fenced lease identity and
generation, reviewed reconciliation evidence, and configured storage/protection
adapters.

Persisted checkpoints remain untrusted data and grant no authority. Model/tool content,
adapter responses, clocks outside the reviewed clock boundary, external systems,
restored storage, backup contents, and historical allow decisions are not trusted as
current authority.

Timing and partial failure are adversarial inputs. The reviewed surface includes
before/after commit faults, ambiguous acknowledgement, truncation/corruption/rollback,
lease loss/takeover, concurrent recovery, `PREPARED`/`STARTED` process loss,
indeterminate reconciliation, live configuration changes, deadline/budget/cancellation
changes, retention races, stale backup restoration, retry exhaustion, and shutdown
during recovery.

## Invariant map

- Invariant 1: RFC-0028 remains the sole durable-agent state machine.
- Invariant 2: RFC-0037 creates no authority by itself.
- Invariant 3: A checkpoint remains untrusted data and grants no authority.
- Invariant 4: Restart never reuses a prior authorization as current authority.
- Invariant 5: Restart never restores an expired, consumed, revoked, or mismatched approval.
- Invariant 6: Restart never increases the configured or remaining execution budget.
- Invariant 7: Restart never creates a later total deadline for an existing run.
- Invariant 8: Downtime counts against a finite total deadline unless an existing RFC defines a stricter rule.
- Invariant 9: Every resumed protected operation receives the same fresh canonical authorization required without a restart.
- Invariant 10: Current configuration and current dependency identity win over persisted metadata.
- Invariant 11: An unknown durable mutation outcome is never blindly repeated.
- Invariant 12: Unknown durable mutation outcome is resolved by exact re-read, version comparison, sequence comparison, digest comparison, and transition validation.
- Invariant 13: A successful re-read must prove the intended exact mutation before it is treated as committed.
- Invariant 14: Absence of the intended exact mutation permits a new mutation attempt only when current version/fencing preconditions still hold.
- Invariant 15: Every recovery mutation requires the current lease identifier and fencing generation.
- Invariant 16: New lease acquisition creates a strictly newer fencing generation as defined by RFC-0028.
- Invariant 17: Every stale-worker mutation path fails closed after takeover.
- Invariant 18: A stale worker cannot complete, cancel, reconcile, clean up, or overwrite a newer run.
- Invariant 19: Lease-owner belief is never sufficient evidence of ownership.
- Invariant 20: Store-side conditional mutation and fencing remain authoritative.
- Invariant 21: Two concurrent recoverers cannot both transition one run as current owners.
- Invariant 22: Process loss after an external attempt reached STARTED never causes automatic replay.
- Invariant 23: Missing terminal evidence never proves that an external effect failed.
- Invariant 24: An indeterminate external attempt remains indeterminate until reviewed evidence proves a permitted disposition.
- Invariant 25: A later fresh attempt is permitted only after evidence establishes that the prior operation was not accepted or after an explicitly reviewed safe disposition.
- Invariant 26: Idempotency keys reduce duplicate risk but are not exactly-once proof.
- Invariant 27: Checkpoint corruption, truncation, substitution, rollback, unsupported versions, and non-canonical encoding fail closed.
- Invariant 28: Checkpoint chains never silently skip a sequence.
- Invariant 29: Restore ambiguity cannot resurrect a known terminal run automatically.
- Invariant 30: Tombstone anti-resurrection metadata wins over stale active records when freshness can be established.
- Invariant 31: When store freshness cannot be established, automatic recovery pauses and requires explicit administration rather than guessing.
- Invariant 32: Deadline expiry during downtime prevents new model or tool work after restart.
- Invariant 33: Cancellation known before recovery prevents new model or tool work.
- Invariant 34: Budget accounting is monotonic across every successful checkpoint transition.
- Invariant 35: Failed or unknown checkpoint writes cannot duplicate budget credit.
- Invariant 36: Recovery attempts themselves are finite and bounded.
- Invariant 37: Repeated crash/restart cannot create an infinite automatic recovery loop.
- Invariant 38: Retention cannot delete an actively and validly leased run.
- Invariant 39: Cleanup with stale fencing cannot delete or mutate current state.
- Invariant 40: Protected content remains opt-in and protected exactly as required by RFC-0028.
- Invariant 41: Reliability diagnostics remain content-free by default.
- Invariant 42: Fault injection is disabled outside explicit deterministic test composition.
- Invariant 43: A model, tool, checkpoint, or external response cannot select a fault point.
- Invariant 44: Production configuration cannot accidentally enable test-only crash injection.
- Invariant 45: Omission of durable configuration preserves existing non-durable behavior.
- Invariant 46: Omission of integrated execution preserves existing non-integrated behavior.
- Invariant 47: RFC-0037 changes reliability evidence, not RFC-0028/RFC-0036 authority semantics.
- Invariant 48: Every release gate for this RFC executes without requiring external network access.

## Reviewed reliability matrix

The S7 release gate maintains a closed mapping from the high-risk matrix classes to
their executable test files. It deliberately does not claim a literal Cartesian product.
The reviewed evidence covers both in-memory and SQLite stores where persistence is
applicable; safe/approval/started/indeterminate/terminal recovery points; lease loss,
takeover, stale workers and concurrent recoverers; committed/not-committed/unknown
mutation outcomes; corruption and rollback; live policy/profile/tool/schema/model/
limit/deadline/cancellation changes; and active/cleanup/tombstone/stale-restore retention
cases.

S7 adds two composed soak families rather than duplicating isolated S1-S6 tests:

1. repeated coordinator epochs over the in-memory store exhaust the persisted automatic
   recovery-attempt budget without mutating the authoritative checkpoint; and
2. repeated SQLite close/reopen cycles exhaust the same budget across process-style
   restart while preserving the exact checkpoint budget/deadline and current witness.

S7 also adds a SQLite `STARTED` irreversible-tool scenario that injects a crash after the
indeterminate transition commits, reopens the store, and proves the successor recovery
does not append or replay the external effect.

## Fault-injection production boundary

`ReliabilityFaultPoint` is a fixed Phoenix-owned vocabulary. The deterministic injector
accepts only that enum and bounded occurrence plans. The ordinary runtime composition
does not expose or retain a fault-injector parameter.

The release gate parses production source and rejects imports of
`phoenix_os.agent.durable_reliability_fake` outside the test utility module itself. The
wheel may contain the inert test utility module because it was introduced as an internal
RFC-0037 test seam, but ordinary packaged runtime composition does not import, configure,
or enable it.

Model output, tool arguments, checkpoints, external responses, policy data, or arbitrary
user content cannot select a fault point.

## Durable mutation and checkpoint integrity

S2 proves exact committed/not-committed/unknown classification, including successful
local acknowledgement without durable evidence, exceptions before commit, exceptions
after commit, unavailable authoritative re-read, conflicting successors, and SQLite
reopen around owned transaction boundaries.

Adversarial codec/store tests reject truncation at multiple boundaries, trailing bytes,
one-byte corruption, digest substitution, skipped/duplicate sequence, wrong previous
digest, cross-run substitution, and rollback to an older valid head.

Unknown outcome never triggers blind repetition and cannot duplicate budget credit.

## Fencing, takeover, and concurrency

S3 proves before/after acquire and renew fault boundaries, SQLite reopen behavior,
monotonic repeated takeover, stale append/completion/cancellation/indeterminate/
reconciliation/cleanup rejection, authoritative post-acquisition re-read, and a
deterministic two-recoverer race in which only one transition commits.

Store-side fencing remains authoritative; a locally plausible stale lease is insufficient.

## Indeterminate effects and reconciliation

S4 proves process-loss boundaries around `PREPARED`, `STARTED`, terminal recording and
reconciliation. A `STARTED` model or tool effect is not transparently replayed.
Reconciliation rejects stale, duplicate, conflicting, or mismatched evidence and a later
fresh attempt requires the reviewed safe disposition already defined by RFC-0028.

The S7 SQLite crash-after-transition scenario adds persistence/reopen evidence around the
same no-replay rule.

## Live revalidation, budgets, deadlines, and cancellation

S5 revalidates current resume authority, profile/dependency identity, tool/effect/schema/
resource/model compatibility, approval state and payload-protection availability.
Current policy and configuration win over persisted metadata.

S6 preserves the original deadline, monotonic base/integrated budgets, stricter current
limits, cancellation continuity, finite persistent recovery attempts, retention fencing,
tombstone anti-resurrection, stale-backup detection and content-free reliability
administration.

The S7 repeated-restart soak proves these finite-recovery properties survive repeated
coordinator recreation and real SQLite reopen cycles.

## Migration and rollback

The companion migration guide records schema version 5, bounded recovery-attempt
bookkeeping, freshness-witness behavior, and the fail-closed rollback procedure. It
explicitly rejects hand-editing schema/witness state to force an older runtime to accept
newer durable state.

No new ADR is required by S7 because this slice adds no new durable state, authority
boundary, persistence format, or production runtime mechanism; it reviews and gates the
S1-S6 design choices already frozen by RFC-0037.

## Package and release boundary

`python scripts/check_reliability_release.py` is release blocking after all prior named
release gates. It runs the reviewed deterministic reliability surface, validates this
invariant map and matrix manifest, verifies the fault-injection production boundary,
builds wheel and sdist, rebuilds a wheel from the sdist, and performs isolated offline
artifact smoke.

S8 finalizes package/repository release metadata for `0.37.0` while preserving the
S1-S7 production implementation and authority model. Tag creation, checksums, artifact
upload, and GitHub Release publication remain separate controlled operations after S8
merge and green post-merge `main` CI.

## Residual risks

RFC-0037 cannot provide distributed consensus, multi-primary mutation, or exactly-once
external effects. It cannot make hostile external content trustworthy, prove behavior
inside unreviewed deployment adapters, reconstruct intentionally unpersisted content, or
turn missing evidence into proof that an effect did not occur.

A freshness witness detects reviewed stale-restore classes; it does not make arbitrary
backup procedures safe. Operators who intentionally remove or rewrite evidence can
destroy the fail-closed signal and must treat that as an operational integrity failure.

## Review conclusion

RFC-0037 is acceptable for the Phoenix OS 0.37.0 release candidate only while this
exact 1..48 invariant map remains complete, the reviewed reliability matrix and soak
tests pass, the dedicated network-free reliability gate and every prior named release
gate remain green, full `scripts/check.ps1` remains green, and package artifacts build,
rebuild from sdist, and install in isolated offline environments.

The final S8 canonical diff/adversarial review confirms that release metadata
finalization plus compatibility-only release-gate wiring did not widen runtime behavior,
durable authority, replay semantics, fencing semantics, recovery semantics, or
external-effect semantics; it also did not weaken deadline/budget/cancellation
continuity, retention/restore fail-closed behavior, content-free diagnostics, or the
test-only fault-injection boundary.

The exact S8 release commit must pass the normal Python 3.12/3.13 CI matrix. Annotated
tag creation, checksums, artifact publication, GitHub Release publication, PR review,
and merge remain separate explicitly authorized release operations, and publication
requires green post-merge `main` CI.
