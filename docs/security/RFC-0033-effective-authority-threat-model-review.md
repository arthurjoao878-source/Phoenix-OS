# RFC-0033 Effective Authority Threat-Model and Security-Invariant Review

## Review method

This review maps RFC-0033 implementation and regression evidence to the
canonical non-amplification rule: every protected operation remains dominated by
its canonical authority boundary regardless of how it is reached. Effective
authority is a point-in-time intersection of current trusted constraints, never
a transferable grant.

## Trust boundaries

Trusted state includes Phoenix-owned principal/session/agent/run identity,
current policy, exact approval records, authoritative resource identity and
generation, cancellation state, reviewed resolvers/adapters, and canonical
subsystem authorizers.

Prompts, model output, tool returns, memory, workspace artifacts, imported data,
clipboard text, process/window labels, diagnostic output, and externally derived
content are data only. They cannot become authority.

Authority inspect/explain is separately authorized, redacted, read-only, and
non-authoritative. Its point-in-time result is not a bearer capability.

## Threat review

- **Subject substitution:** principal, structural session, agent, and run
  identity are independently bound; attribute-derived session identity cannot
  create or preserve session-bound authority.
- **Freshness/TOCTOU:** revocable authority is revalidated after the final
  untrusted wait and before canonical admission.
- **Approval replay:** approval binds exact subject, intent, resource, and
  freshness state rather than acting as ambient confirmation.
- **Resource rebirth:** stale resource generation/version/epoch identities fail
  closed instead of being rebound to a newly created object.
- **Confused deputy:** internal services may not replace the requester with a
  stronger principal to reach a protected effect.
- **Cross-agent borrowing:** parent, child, peer, and resumed runs do not inherit
  each other's current authority merely because they exchange data or results.
- **Capability composition:** reviewed transitions preserve the final canonical
  boundary; effective authority is the intersection of applicable constraints,
  not the union of permissions along the path.
- **Closed-world drift:** an unknown operation or unreviewed mediated transition
  fails closed rather than receiving a guessed boundary.
- **Diagnostic replay:** inspection/explanation is redacted point-in-time data
  and remains non-authoritative.

## Security-invariant review

The dedicated contract, subject-binding, freshness, composition, adversarial,
explain, redaction, security-review, RFC, and release-gate tests cover the
normative RFC-0033 suite. Existing subsystem tests remain the executable proof of
their canonical authorizers; RFC-0033 adds cross-boundary evidence rather than
replacing those authorizers.

The release checker requires the exact six reviewed `phoenix_os.authority`
modules and durable control-plane authority integration, rejects unreviewed extra
authority modules, validates release documents and package archives, rebuilds
from the validated sdist, and performs isolated offline deterministic smoke
validation.

## Residual risks

RFC-0033 does not sandbox arbitrary malicious Python already executing inside
the trusted Phoenix process, provide kernel mandatory access control, prove
external applications have no incidental effects, or provide exactly-once
guarantees for external side effects. Network authority and browser automation
remain outside this RFC.

A malicious trusted adapter that directly bypasses Phoenix mediation remains
outside the containment claim. New protected operations or mediated transitions
require catalog and security review before release.

## Release conclusion

The v0.33.0 release candidate is acceptable only when the complete authority
suite, `python scripts/check_authority_release.py`, normal Phoenix quality
gates, package-boundary validation, and the exact Python 3.12/3.13 CI matrix all
pass for the release commit. No inspection output, approval record, prior policy
decision, or data-bearing capability is accepted as reusable authority.
