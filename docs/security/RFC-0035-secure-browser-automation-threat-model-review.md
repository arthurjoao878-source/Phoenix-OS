# RFC-0035 Secure Browser Automation Threat-Model and Security-Invariant Review

## Review method

This release-hardening review maps the frozen RFC-0035 threat model and all fifty
security invariants to the S1-S7 implementation and executable regression surface.

The dominant rule is:

> Web content is data. Browser state is data. Neither grants Phoenix authority.

RFC-0033 effective-authority composition remains dominant: every protected operation
must terminate at its canonical boundary, and effective authority is the intersection
of current trusted constraints rather than a union of historical decisions.

## Trust boundaries

Trusted state includes Phoenix-owned profile/target identity and generation, exact
allowed origins, finite browser limits, structural subject state, exact session/page/
revision/element identity, current policy/freshness, exact browser intent, current tool
binding when applicable, cancellation/deadline, current DNS/IP admission, and the
reviewed adapter prepare/commit contract.

Untrusted data includes prompts, model output, tool arguments/results, page text,
element labels/values, links, forms, redirect locations, remote response content,
cookies as content-bearing browser state, DNS answers before admission, prior ALLOW
results, snapshots, health output, telemetry, and caller-provided URL-like text.

## Final effect boundary

Adapter preparation, DNS resolution, and other remote-readiness work may be
attacker-influenceable waits. Preparation is zero-effect. After the final such wait,
Phoenix revalidates the current subject, profile generation, session, page revision,
exact action/intent, tool authority when applicable, destination admission,
cancellation, and deadline.

No observer, audit, Event Bus, log, metric, health, or inspection await is inserted
between final admission and commit. Content-free observation is scheduled best-effort
outside the protected critical window.

If a remote or external effect may already have started, later ambiguity is
`INDETERMINATE` and is never transparently retried.

## Invariant map

- Invariant 1: Browser automation is disabled unless explicitly configured.
- Invariant 2: Enabling the subsystem grants no permission, approval, session, page, cookie, network, host, workspace, tool, model, or other authority.
- Invariant 3: Every profile uses a stable Phoenix-owned ID and positive server-owned generation.
- Invariant 4: Initial navigation targets are immutable server-owned profile state.
- Invariant 5: Caller/model contracts contain no arbitrary URL selection.
- Invariant 6: Allowed origins are finite exact tuples; wildcard origin authority is absent.
- Invariant 7: Hosted origins require verified HTTPS.
- Invariant 8: Plain HTTP is confined to explicit loopback mode.
- Invariant 9: Ambient proxy configuration is not browser routing authority.
- Invariant 10: Browser traffic does not inherit or imply `network.http.request`.
- Invariant 11: `network.http.request` does not imply browser authority.
- Invariant 12: Every protected browser operation crosses its exact canonical browser action.
- Invariant 13: No generic `browser.execute` surface exists.
- Invariant 14: `tool.invoke` alone does not imply a browser action.
- Invariant 15: Browser authority alone does not imply `tool.invoke`.
- Invariant 16: Effective authority is the intersection of all currently valid constraints.
- Invariant 17: Internal services preserve the original requester and cannot substitute a stronger principal.
- Invariant 18: Sessions bind to the exact structural authority subject that opened them.
- Invariant 19: Session/page/element IDs, snapshots, and prior ALLOW decisions are non-bearer data.
- Invariant 20: v0.35.0 permits exactly one top-level page per session.
- Invariant 21: Positive page revisions are freshness identities and stale revisions fail closed.
- Invariant 22: Elements use opaque Phoenix-owned IDs bound to one exact page revision.
- Invariant 23: CSS, XPath, coordinates, pixel targets, DOM paths, and native handles are not public effect selectors.
- Invariant 24: Page snapshots are bounded and exclude raw HTML and arbitrary DOM attributes.
- Invariant 25: Page content, labels, links, forms, redirect targets, and accessibility text are untrusted.
- Invariant 26: JavaScript and caller-supplied script execution are disabled.
- Invariant 27: Autonomous network-capable page channels are disabled.
- Invariant 28: Automatic subresources, frames, popups, and multiple pages are blocked.
- Invariant 29: Downloads and uploads are outside v0.35.0.
- Invariant 30: Password/file and secret/host-transfer controls are not ordinary fill targets.
- Invariant 31: Fill input is bounded and exact-input intent is digest-bound.
- Invariant 32: Click is conservatively treated as potentially effectful.
- Invariant 33: Click-derived navigation/form requests bind to the exact current element/page/effect plan.
- Invariant 34: Every top-level browser request requires current exact-origin and DNS/IP admission.
- Invariant 35: Every DNS answer must pass policy; unsafe mixed sets fail closed.
- Invariant 36: Redirects are finite and every next destination is re-admitted.
- Invariant 37: Redirect/page/form data cannot create an origin grant or new authority grant.
- Invariant 38: Cookies are bounded ephemeral internal state and are not caller/model/tool-visible.
- Invariant 39: Cookies and other browser state never manufacture browser authority.
- Invariant 40: Persistent storage and persistent user-data directories are absent from v0.35.0.
- Invariant 41: Concrete adapters separate zero-effect preparation from protected commit.
- Invariant 42: Final revalidation covers subject, profile, session, page/revision, intent, applicable tool authority, destination, cancellation, and deadline.
- Invariant 43: No new attacker-controlled blocking wait occurs after final admission before commit.
- Invariant 44: Page disclosure requires separate fresh `browser.page.read` authority.
- Invariant 45: Remote response content is untrusted and cannot manufacture follow-on operations.
- Invariant 46: Potentially effectful operations receive no transparent retry after possible effect start.
- Invariant 47: Ambiguous post-effect failure is `INDETERMINATE`.
- Invariant 48: Routine observability is content-free and cannot become authority.
- Invariant 49: Runtime lifecycle controls availability only and grants no browser authority.
- Invariant 50: Omitted browser configuration preserves Phoenix OS v0.34.0 behavior.

## Adversarial release cases

Release-blocking coverage includes arbitrary URL/scheme/host/port/proxy/DNS/certificate/
executable/profile selection, wildcard or redirect origin widening, direct and derived
SSRF, DNS rebinding, mixed safe/unsafe answers, stale page/element retargeting,
selector/XPath/coordinate/native-handle escape, hidden password/file-control exposure,
script/DevTools escape, background network channels, frames/popups/subresources,
download/upload smuggling, cookie leakage, cross-principal/session/agent/run reuse,
replayed ALLOW/tool approval/snapshot observations, generation substitution, revocation
during preparation, cancellation/deadline races, observer-induced waits, remote-content
authority escalation, and retry after indeterminate effect.

The deterministic adapter proves the reviewed zero-effect contract and fail-closed state
machine without performing real networking. Any production adapter must independently
satisfy the same contract before release.

## Runtime, observation, and administration

Standalone service ownership remains supported. Optional Runtime ownership changes only
availability and bounded shutdown. Normal closing rejects new operations, drains
admitted work, closes ephemeral sessions, and closes owned adapter resources. Borrowed
policy/freshness/resolver/Event Bus/audit/observability dependencies remain borrowed.

Security quarantine is distinct from ordinary lifecycle unavailability and retains the
operation-disabled fail-closed semantics.

Operation telemetry contains only a server-generated operation ID, finite operation
class/outcome, effect-start fact, and bounded duration. Event payloads contain no page
content. Metric labels remain finite and do not use operation IDs as labels.

`BrowserAutomationAdministration` requires `browser.health.read` and exposes only a
schema-versioned content-free service snapshot. It does not enumerate profiles,
sessions, pages, elements, destinations, cookies, policy decisions, authority objects,
or remote content.

## Package and publication boundary

`python scripts/check_browser_automation_release.py` requires the exact reviewed browser
module set, complete browser regression suite, RFC/migration/ADR/security documents,
safe wheel/sdist paths, matching metadata, a rebuilt-sdist wheel, and isolated offline
installed smoke behavior.

The package smoke performs no DNS query, socket connection, HTTP exchange, browser
process launch, navigation, click, fill, page read, credential access, or external
effect.

The Python 3.12/3.13 CI matrix must run the dedicated browser gate after the existing
network-egress gate. S7 does not change package version, release notes, tags, or
publication metadata. Those operations belong to S8 and remain separately reviewed and
authorized.

## Residual risks

RFC-0035 cannot make hostile remote content trustworthy, provide exactly-once remote
effects, revoke bytes already delivered to a remote peer, or prove security properties
of a production browser engine that is not bundled in Phoenix OS. An operator who
configures broader origins or explicit network ranges intentionally expands the trusted
configuration scope and must review that configuration.

## Release conclusion

RFC-0035 is acceptable for the Phoenix OS 0.35.0 release candidate only when all fifty invariants
remain mapped, the complete browser targeted suite and global quality checks
are green, the dedicated browser package gate and package boundaries pass, and the final
S8 canonical diff/adversarial review confirms that release metadata finalization plus
compatibility-only release-gate wiring did not widen the frozen browser architecture or alter
runtime behavior, package authority, browser semantics, or network semantics.

The exact release commit must then pass the normal Python 3.12/3.13 CI matrix. Annotated
tag creation, artifact/checksum publication, GitHub Release publication, PR review, and
merge remain separate explicitly authorized release operations.
