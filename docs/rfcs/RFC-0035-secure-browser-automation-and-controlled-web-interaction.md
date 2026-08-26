# RFC-0035: Secure Browser Automation and Controlled Web Interaction

- Status: Draft
- Target release: Phoenix OS v0.35.0
- Owners: Phoenix OS maintainers
- Architecture freeze: 2026-08-25
- Depends on: RFC-0002, RFC-0003, RFC-0004, RFC-0005, RFC-0006, RFC-0009,
  RFC-0010, RFC-0027, RFC-0033, and RFC-0034

## Summary

RFC-0035 defines an optional, fail-closed browser-automation boundary for Phoenix OS.
It allows a caller or agent to interact with a finite server-owned browser profile through
opaque Phoenix identities and exact browser operations without exposing a generic browser,
arbitrary URL fetcher, JavaScript evaluator, host automation channel, or unrestricted
network client.

RFC-0033 already reserved secure browser automation for RFC-0035, and RFC-0034 deliberately
left browser sessions, DOM state, JavaScript execution, forms, cookies, navigation, and
browser authority outside controlled HTTP egress.

The dominant rules are:

> **Web content is data. Browser state is data. Browser effects require fresh, exact,
> browser authority.**

and, from RFC-0033:

> **Every protected operation remains dominated by its canonical authority boundary,
> regardless of how that operation is reached.**

Browser authority is independent of `tool.invoke`, `network.http.request`, host, workspace,
memory, model, webhook, and other Phoenix authority. Composition uses intersection, never
inheritance or union.

## Motivation

Phoenix OS v0.34.0 can perform server-owned controlled HTTP operations, but it intentionally
is not browser-like. It has no DOM, browser session, cookie jar, navigation graph, form
interaction, element identity, or JavaScript execution.

Agent and operator workflows nevertheless need a reviewed web-interaction boundary. Adding a
generic Playwright/Selenium-style API would be unsafe because model output could otherwise
select arbitrary URLs, selectors, coordinates, scripts, browser executables, profiles,
downloads, uploads, proxies, credentials, or cross-origin effects.

RFC-0035 therefore adds a narrower browser substrate whose externally reachable behavior is
defined by Phoenix-owned profiles, opaque state identities, exact operation authority, bounded
page observations, stale-safe interaction, and separate browser-network admission.

## Principle

A web page, DOM node, link, form, redirect, cookie, response header, accessibility label, or
visible instruction can inform a requested browser action. None of them can manufacture the
authority required to perform that action.

A successful prior browser authorization, page snapshot, element identifier, session
identifier, navigation result, tool result, health snapshot, or inspection result is not a
bearer capability.

## Goals

- Browser automation disabled by default
- Immutable server-owned browser profiles with positive generations
- No implicit browser/session/page/tool/grant creation during upgrade
- Exact browser actions rather than a generic `browser.execute`
- One bounded page per browser session in v0.35.0
- Opaque Phoenix-owned session, page, and element identities
- Page-revision binding so stale element actions fail closed
- Bounded content-minimized page observation; no raw DOM or raw HTML surface
- Server-owned initial navigation targets; no caller-selected arbitrary URL
- Finite exact allowed-origin sets; no wildcard origin authority
- Verified HTTPS for hosted web origins
- Explicit loopback-only HTTP mode for local development/integration
- DNS/IP destination admission for every browser-originated top-level request
- Finite redirect handling with destination re-admission
- JavaScript disabled in the v0.35.0 core contract
- Automatic subresource, iframe, popup, worker, service-worker, WebSocket, WebRTC, media,
  download, and upload activity blocked
- Ephemeral bounded cookies kept internal to the browser session and never exposed as tool data
- Fresh exact browser authority for session, navigation, observation, fill, click, and close
- RFC-0033 subject, resource, intent, freshness, and non-amplification preservation
- Existing RFC-0027 `tool.invoke` authority remains independent for model-originated operations
- No transparent retry after a browser-originated remote effect may have started
- Cooperative cancellation, finite deadlines, finite concurrency, and bounded shutdown
- Content-free routine observability and separately authorized redacted inspection
- Runtime-owned optional lifecycle
- Deterministic fake adapter and adversarial security tests
- Compatibility with Phoenix OS v0.34.0 by omission

## Non-goals

- Arbitrary URL navigation or arbitrary URL fetching
- A general-purpose Playwright, Selenium, WebDriver, CDP, or browser-control API
- Bundling Chromium, Firefox, WebKit, Playwright, Selenium, or a browser executable in the core
- Caller-selected browser executable, command line, profile directory, extension, proxy, DNS
  resolver, certificate policy, environment, user-data directory, or native handle
- Arbitrary CSS selectors, XPath, coordinates, keyboard/mouse automation, or pixel clicking
- Arbitrary JavaScript evaluation or caller-supplied script execution
- JavaScript-enabled pages in v0.35.0
- Background fetch, XHR, beacon, WebSocket, WebRTC, service worker, worker, or push behavior
- Automatic iframe, image, stylesheet, font, media, prefetch, preload, or other subresource loads
- Multiple pages, tabs, popups, or browser windows per session in v0.35.0
- Browser downloads
- Browser uploads or host-filesystem file pickers
- Automatic transfer to or from RFC-0031 workspaces
- Password-manager, credential-autofill, secret-entry, or raw credential APIs
- Persistent browser profiles or persistent cookies across Phoenix restart
- Browser extension installation
- CAPTCHA solving, anti-bot bypass, fingerprint spoofing, or stealth automation
- Replacing RFC-0034 controlled HTTP operations
- Treating browser traffic as an implicit `network.http.request` grant
- Raw TCP/UDP/socket authority
- Exactly-once guarantees for remote browser effects
- Transparent retry after an indeterminate remote effect
- Treating trusted TLS as proof that page content is safe
- A hostile-code sandbox for installed browser adapters

## Terminology

- **Browser profile:** immutable server-owned configuration for one reviewed browser-automation
  scope.
- **Profile ID:** stable Phoenix-owned identifier for a browser profile.
- **Profile generation:** positive server-owned version distinguishing changed profile definitions.
- **Navigation target:** immutable server-owned initial destination selected by a stable target ID.
- **Allowed origin:** exact server-owned `(scheme, host, port)` tuple admitted by the profile.
- **Browser session:** bounded ephemeral Phoenix-owned browser state bound to one authority subject
  and one profile generation.
- **Page:** the single bounded top-level document owned by one browser session in v0.35.0.
- **Page revision:** positive Phoenix-owned freshness identity changed whenever navigable or
  interactable page state is replaced or invalidated.
- **Element ID:** opaque Phoenix-owned identifier for one interactable element observed at one exact
  page revision.
- **Page snapshot:** bounded untrusted observation of reviewed page text and interactable element
  metadata. It is data, not authority.
- **Browser effect plan:** immutable server-derived description of the exact state or remote effect
  an interaction would attempt if finally admitted.
- **Prepared browser effect:** adapter-owned zero-effect state that has completed attacker-influenceable
  preparation but has not yet committed the protected state/remote effect.
- **Remote browser effect:** outbound request bytes or other externally observable browser action
  caused by an admitted browser operation.

## Architecture

```text
Caller / Agent
    |
    +-- tool.invoke boundary when model-originated
    |
    +-- BrowserAutomationService
           |
           +-- current subject freshness
           +-- exact browser profile generation
           +-- exact session/page/revision identity
           +-- canonical browser action/resource
           +-- exact operation intent
           |
           +-- BrowserAdapter
           |      |
           |      +-- prepare zero-effect operation
           |      +-- deterministic page/element identity
           |      +-- commit only after final admission
           |
           +-- BrowserNetworkAdmission
                  |
                  +-- exact profile origin policy
                  +-- DNS answer admission
                  +-- verified TLS policy
                  +-- finite redirect re-admission
```

The core defines contracts, mediation, authority, lifecycle, deterministic fakes, and release
validation. It does not bundle a production browser engine. Concrete browser engines remain
reviewed external adapters and MUST satisfy the same prepare/commit, network-admission,
JavaScript-disabled, subresource-blocked, and stale-identity contracts before they can claim
RFC-0035 compatibility.

## Canonical browser actions

RFC-0035 introduces a finite initial action set:

```text
browser.session.open
browser.session.close
browser.page.navigate
browser.page.read
browser.element.fill
browser.element.click
```

There is no generic `browser.execute`.

The intended canonical resource grammar is:

```text
browser:<profile-id>/generation:<generation>
browser:<profile-id>/generation:<generation>/session:<session-id>
browser:<profile-id>/generation:<generation>/session:<session-id>/page:<page-id>/revision:<revision>
browser:<profile-id>/generation:<generation>/session:<session-id>/page:<page-id>/revision:<revision>/element:<element-id>
```

`browser.session.open` is authorized against the exact profile generation and a server-owned
session-open intent. Later actions additionally bind the exact session. Page and element actions
bind the current page revision. Element effects bind the exact opaque element ID plus the
server-derived effect plan and normalized caller input, when applicable.

No browser action implies another browser action.

`browser.page.read` does not imply click or fill. Click does not imply fill. Session authority
does not imply page authority. Browser authority does not imply network, tool, model, host,
workspace, memory, webhook, or other authority.

## Effective authority

For a model-originated browser operation:

```text
effective authority
    =
tool.invoke
    INTERSECT
exact browser action
    INTERSECT
current principal/session/agent/run
    INTERSECT
current browser profile generation
    INTERSECT
current browser session/page/revision
    INTERSECT
exact element/effect/input intent when applicable
    INTERSECT
current policy
    INTERSECT
browser network admission when a remote request is possible
    INTERSECT
cancellation/deadline state
```

`tool.invoke` remains the RFC-0027 canonical tool boundary. Browser actions are separately added
to the RFC-0033 closed-world authority catalog. A tool allow cannot replace browser authorization,
and browser authorization cannot replace tool authorization.

`network.http.request` remains the RFC-0034 boundary for RFC-0034 controlled HTTP operations.
RFC-0035 browser traffic is not silently routed through `NetworkEgressService` and does not acquire
`network.http.request`. Instead, browser-originated top-level requests are part of the exact admitted
browser operation and are constrained by RFC-0035 browser-network admission. This separation is
intentional because a browser navigation graph is not semantically equivalent to one server-owned
RFC-0034 HTTP operation.

## Server-owned browser profiles

A `BrowserProfile` contains at least:

- stable profile ID;
- positive generation;
- finite exact allowed-origin set;
- one or more immutable initial navigation targets;
- hosted HTTPS versus explicit loopback HTTP destination mode;
- finite DNS-answer and redirect bounds;
- finite session, page, snapshot, element, cookie, input, duration, and concurrency limits;
- fixed JavaScript-disabled policy;
- fixed subresource-blocked policy;
- fixed popup/multi-page-blocked policy;
- fixed download/upload-blocked policy; and
- adapter identity/configuration that callers cannot override.

Allowed origins are exact tuples. Wildcard hosts, wildcard ports, arbitrary schemes, caller-provided
origin patterns, and response-provided origin grants are outside v0.35.0.

Changing any security-relevant profile field requires a new positive generation. Existing sessions
remain bound to their original complete immutable profile and fail closed when the current configured
profile no longer matches that snapshot.

## Navigation targets

Initial navigation never accepts a URL from the caller or model.

The caller selects only a stable server-owned navigation-target ID already present in the current
profile. A target fixes its exact initial scheme, host, port, path, and query.

The browser may later derive a candidate navigation from an observed link, form, or finite redirect.
That candidate is untrusted data. It must remain inside the exact profile origin set, pass current
destination admission, and be bound into the exact effect intent before remote request bytes can
begin.

Fragments are local data and grant no network authority.

## Browser network admission

Every top-level browser request that can emit request bytes MUST use the active profile's browser
network policy.

Hosted destinations require HTTPS with verified hostname/certificate validation. Plain HTTP is
supported only for an explicit loopback profile mode.

For each destination candidate Phoenix MUST:

1. canonicalize only the server-derived candidate;
2. require an exact allowed origin;
3. resolve through the reviewed browser-network resolver;
4. bound the number of DNS answers;
5. parse every answer as a literal address;
6. reject the complete set if any address violates the active destination policy;
7. bind the admitted destination set into the prepared browser effect;
8. connect only through an adapter contract that cannot silently select an unadmitted destination;
9. preserve the canonical hostname for hosted TLS validation; and
10. ignore ambient proxy configuration.

A concrete adapter MAY reuse reviewed RFC-0034 destination-admission primitives when behavior is
provably equivalent, but it MUST NOT treat an RFC-0034 ALLOW decision or `NetworkEgressService`
result as browser authority.

## Redirects

Finite redirects are allowed only as part of one already admitted top-level browser operation.

Each redirect target is untrusted data and MUST be canonicalized, checked against the current exact
allowed-origin set, DNS/IP-admitted, and bounded by the profile redirect limit before the browser can
continue.

A redirect never creates a new origin grant, browser permission, tool permission, network permission,
cookie disclosure permission, or follow-on protected operation.

`Refresh` response headers, HTML meta refresh, script navigation, popup navigation, and other
automatic navigation channels are blocked in v0.35.0.

## JavaScript and autonomous page behavior

JavaScript is disabled unconditionally by the v0.35.0 core contract.

The browser surface exposes no `evaluate`, `execute_script`, expression, console, DevTools, CDP,
extension, or equivalent caller-controlled scripting channel.

Service workers, web workers, shared workers, background fetch, XHR/fetch, beacons, WebSockets,
WebRTC, push, notifications, geolocation, camera, microphone, clipboard, and other autonomous or
device-capability channels are outside v0.35.0.

This restriction prevents page-controlled code from creating an unbounded remote-effect stream after
one browser operation has been admitted.

## Subresources, frames, popups, and downloads

v0.35.0 permits only the top-level document request graph needed for an explicit navigation or
element effect.

Images, stylesheets, fonts, media, iframes, object/embed content, prefetch, preload, module loads,
favicon fetches, and other subresources are blocked.

There is exactly one top-level page per session. Popups, `target=_blank`, additional tabs/windows,
and page creation by content are blocked.

Downloads are blocked before bytes are persisted or exposed. File uploads and file-picker access are
blocked. A future workspace transfer feature would require a separately reviewed composition in
which browser transfer authority remains intersected with the exact RFC-0031 workspace boundary.

## Session and page identity

A browser session is created only after `browser.session.open` authorization and is bound to:

- the exact authority subject;
- the exact complete browser profile and generation;
- a Phoenix-owned opaque session ID;
- finite server-owned lifetime/deadline state; and
- one Phoenix-owned page ID.

A session ID is state identity, not bearer authority.

A session cannot be transferred between principals, sessions, agents, or runs. Structural subject
mismatch fails closed even when the opaque session ID is known.

The single page begins without remote content. Successful navigation replaces page state and advances
the positive page revision. Any operation that invalidates the current document or interactable
element set advances the revision before new element identities are exposed.

## Page observation

`browser.page.read` returns a bounded `BrowserPageSnapshot` rather than raw HTML or a general DOM.

The snapshot may contain only reviewed fields such as:

- current page revision;
- bounded visible/document text;
- bounded title;
- canonical current origin/path data when safe to expose;
- a bounded list of interactable elements;
- opaque element IDs;
- finite semantic role/type;
- bounded visible/accessibility name;
- bounded non-secret current value when explicitly safe; and
- coarse interaction availability.

Snapshots exclude raw HTML, script/style content, arbitrary attributes, event handlers, browser
internals, network headers, cookies, storage, credentials, certificate details, native handles, and
authority objects.

Password/file inputs and other secret-bearing or host-transfer controls are not exposed as fillable
elements. Sensitive values MUST be omitted or redacted by the adapter contract.

Page content and accessibility text remain untrusted data.

## Opaque elements and stale-safe effects

The caller or model cannot target browser effects using CSS selectors, XPath, DOM paths, coordinates,
screen pixels, node indexes, native handles, or caller-chosen element identifiers.

`BrowserElementId` values are Phoenix-owned opaque identifiers valid only for one exact session, page,
and revision.

Before `browser.element.fill` or `browser.element.click`, Phoenix resolves the element from current
trusted adapter state and builds a deterministic effect plan. The plan binds the exact current
revision, element identity, relevant element semantics, normalized input, and any candidate
navigation/form method/target/body digest that the action could produce.

If the page revision, element identity, relevant semantics, form data, candidate destination, or other
intent-bound state changes before commit, the effect fails closed as stale rather than retargeting to
a "similar" element.

## Fill

`browser.element.fill` accepts only bounded Unicode text and only for the finite reviewed element types
defined by S1 contracts.

It cannot target password inputs, file inputs, hidden controls, browser chrome, arbitrary
content-editable scripting surfaces, native dialogs, or host clipboard state.

Because JavaScript is disabled, fill does not intentionally dispatch caller-controlled script.
Nevertheless it remains a protected browser-state mutation and requires exact current authority.

The normalized fill value participates in the exact authority intent through a deterministic digest.
Routine observability never records the value.

## Click

Every click is treated conservatively as potentially effectful.

Click operates only on one current opaque element ID. The prepared effect plan determines whether the
click is local-only or can cause one top-level navigation/form request. If a remote request is
possible, the exact method, destination candidate, and body digest are bound into the intent and
browser-network admission is required.

Phoenix never assumes a GET is harmless merely because the remote site labels a control as a link.

There is no coordinate click, double-click, drag/drop, arbitrary keypress, hover-triggered network
channel, or generic gesture API in v0.35.0.

## Cookies and browser storage

v0.35.0 may maintain a bounded ephemeral cookie jar only inside one browser session.

Cookie state:

- is never caller/model/tool-visible;
- is never returned by `browser.page.read`;
- is never emitted in routine logs, metrics, events, audit details, or errors;
- is never persisted across Phoenix restart;
- cannot escape the exact allowed-origin policy;
- is cleared when the session closes; and
- cannot be imported from or exported to the host, workspace, another session, or another profile.

LocalStorage, SessionStorage, IndexedDB, Cache Storage, credential stores, password managers, and
persistent browser user-data directories are outside v0.35.0.

Cookies are state, not authority. Possessing a session ID does not authorize cookie use, and cookie
presence does not authorize any browser action.

## Prepare/commit and TOCTOU closure

Concrete adapters MUST separate attacker-influenceable preparation from protected effect commit.

Preparation may perform bounded work needed to resolve current page state, derive the exact effect
plan, resolve/admit a network destination, and establish adapter-owned zero-effect readiness. It MUST
NOT emit remote request bytes, mutate browser-visible state, disclose protected page content, or
perform the requested click/fill/navigation effect.

After the final attacker-controlled wait, `BrowserAutomationService` MUST revalidate all applicable
revocable state, including:

- current structural authority subject;
- current complete browser profile and generation;
- current session binding and lifetime;
- current page and revision;
- current opaque element and effect plan when applicable;
- current exact browser authorization;
- current exact `tool.invoke` authorization when model-originated;
- current destination admission when a remote request is possible; and
- cancellation/deadline state.

After that final admission there MUST be no new attacker-controlled blocking wait before commit.
If a concrete adapter cannot provide that guarantee, it is not compatible with the v0.35.0 protected
effect boundary.

Once remote request bytes or another external effect may have started, Phoenix performs no transparent
retry. Ambiguous outcomes are `INDETERMINATE`.

## Disclosure freshness

Navigation and click results do not automatically return remote page content.

Remote response content is stored as untrusted internal page state. A later `browser.page.read`
requires its own fresh exact authorization and current subject/session/page validation before any
bounded page snapshot is disclosed.

This prevents a long remote response wait from turning an earlier navigation allow into reusable
authority to disclose content after revocation.

## Agent tool composition

RFC-0035 may add reviewed mediated transitions from `tool.invoke` to the finite browser actions.

A `BrowserToolBinding` is server-owned and binds at least:

- exact agent ID;
- exact tool ID;
- exact browser action;
- exact browser profile and generation; and
- any fixed initial navigation target required by that tool.

Tool arguments never contain arbitrary URLs, selectors, XPath, coordinates, scripts, browser
executables, proxies, cookie material, credentials, host paths, or authority objects.

Model-originated browser operations must pass both the normal RFC-0027 tool boundary and the final
browser boundary. Final tool revalidation occurs after the last attacker-controlled preparation wait
when the adapter requires final effect admission.

Browser results remain untrusted tool data and cannot manufacture follow-on browser, network, host,
workspace, memory, model, or delegation authority.

## Runtime lifecycle

Browser automation is omitted by default.

When configured, `PhoenixRuntime` may own a bounded `BrowserAutomationService`. Runtime state controls
availability and shutdown only; it never grants browser authority.

Runtime shutdown rejects new sessions/effects, drains already admitted work within finite bounds,
closes ephemeral browser sessions, clears cookie state, and closes owned adapter resources in
deterministic order. Borrowed policy, identity, Event Bus, audit, observability, and resolver
dependencies are not closed by the browser service.

## Observability and inspection

Routine browser observations are content-free.

They may include only finite identifiers/classes such as a server-generated operation ID, fixed
operation kind, fixed outcome, whether a remote effect may have started, and bounded duration.

Routine logs, metrics, Event Bus facts, audit details, and errors MUST NOT include page text, element
labels, fill values, URLs beyond separately reviewed redacted origin data, request/response bodies,
cookies, storage, credentials, DNS answers, literal addresses, certificate details, browser native
handles, raw adapter errors, authority intents, or policy decisions.

Any read-only browser health/inspection surface is separately authorized and point-in-time only. It
cannot be reused as browser authority.

## Failure model

Public failures are content-minimized and use a finite result classification.

Before protected effect commit, expected classes include:

```text
REJECTED
STALE
CANCELLED
TIMED_OUT
FAILED
```

After a remote or external effect may have started, ambiguous failure is:

```text
INDETERMINATE
```

No public error reveals secrets, cookies, raw remote content, policy rules, DNS/IP details, native
browser internals, or exception text.

## Security invariants

1. Browser automation is disabled unless explicitly configured.
2. Enabling browser automation grants no permission, approval, session, page, cookie, network, host,
   workspace, tool, model, or other authority automatically.
3. Every browser profile has a stable Phoenix-owned profile ID and positive server-owned generation.
4. Every initial navigation target is server-owned and immutable within a profile generation.
5. Callers and models cannot provide arbitrary URLs.
6. Allowed origins are finite exact tuples; wildcard origin authority is outside v0.35.0.
7. Hosted origins require verified HTTPS.
8. Plain HTTP is limited to explicit loopback mode.
9. Ambient proxy configuration is ignored.
10. Browser traffic does not inherit or imply `network.http.request`.
11. `network.http.request` does not imply browser authority.
12. Every browser protected operation crosses its exact canonical browser action boundary.
13. There is no generic `browser.execute`.
14. `tool.invoke` does not imply a browser action.
15. Browser authority does not imply `tool.invoke`.
16. Effective authority is the intersection of all currently valid constraints, never their union.
17. Internal services preserve the original requester and cannot substitute a stronger principal.
18. Browser sessions are bound to the exact structural authority subject that opened them.
19. Session IDs, page IDs, element IDs, snapshots, and prior ALLOW decisions are not bearer authority.
20. v0.35.0 has exactly one top-level page per browser session.
21. Page revisions are positive freshness identities and stale revisions fail closed.
22. Elements are addressed only by opaque Phoenix-owned IDs bound to one exact page revision.
23. CSS selectors, XPath, coordinates, pixel targets, DOM paths, and native handles are not public
    effect selectors.
24. Page snapshots are bounded, reviewed, and exclude raw HTML and arbitrary DOM attributes.
25. Page content, labels, links, forms, redirect targets, and accessibility text are untrusted data.
26. JavaScript and caller-supplied script execution are disabled.
27. Autonomous network-capable page channels are disabled.
28. Automatic subresources, frames, popups, and multiple pages are blocked.
29. Downloads and uploads are blocked in v0.35.0.
30. Password/file inputs and secret/host-transfer controls are not exposed as ordinary fill targets.
31. Fill input is bounded and exact-input intent is digest-bound.
32. Click is treated conservatively as potentially effectful.
33. Any click-derived navigation/form request is bound to the exact current element/page/effect plan.
34. Every top-level browser request passes current exact-origin and DNS/IP destination admission.
35. Every DNS answer must pass destination policy; unsafe mixed answer sets fail closed.
36. Redirects are finite and each target is re-admitted before continuation.
37. Redirect, page, or form data never creates an origin grant or a new authority grant.
38. Cookies are bounded ephemeral internal state and never caller/model/tool-visible.
39. Cookies and other browser state never manufacture browser authority.
40. Persistent browser storage and persistent user-data directories are outside v0.35.0.
41. Concrete adapters separate zero-effect preparation from protected commit.
42. After the final attacker-controlled wait, current subject, profile, session, page/revision,
    action/intent, tool authority when applicable, destination admission, cancellation, and deadline
    are revalidated before commit.
43. No new attacker-controlled blocking wait is inserted between final admission and commit.
44. Page content disclosure requires a separate fresh `browser.page.read` authorization.
45. Remote response content is untrusted data and does not manufacture a follow-on operation.
46. Potentially effectful browser operations are never transparently retried after effect start may
    have occurred.
47. Ambiguous post-effect failures are `INDETERMINATE`.
48. Routine observability is content-free and cannot become authority.
49. Runtime lifecycle state controls availability only and does not grant browser authority.
50. Existing Phoenix OS v0.34.0 behavior is unchanged when browser automation configuration is absent.

## Threat model

Release-blocking adversarial cases include:

- arbitrary URL, scheme, host, port, proxy, DNS, certificate, executable, or profile selection;
- wildcard-origin or redirect-based destination widening;
- SSRF through direct navigation, redirect, form action, or DNS rebinding;
- mixed safe/unsafe DNS answer sets;
- stale page/element retargeting;
- CSS/XPath/coordinate escape hatches;
- hidden password/file-control exposure;
- model-supplied JavaScript or DevTools escape;
- background JavaScript/network activity after one admission;
- iframe/popup/subresource/download/upload authority smuggling;
- cookie leakage or cross-session cookie reuse;
- cross-principal, cross-session, cross-agent, or cross-run session reuse;
- reuse of old ALLOW, tool approval, page snapshot, or element observation as bearer authority;
- profile-generation substitution;
- policy/session revocation during adapter or destination preparation;
- cancellation/deadline races;
- observer/audit waits inserted into the final admission window;
- remote content attempting to instruct a stronger protected action;
- transparent retry after an indeterminate effect; and
- a concrete adapter that cannot prove zero-effect preparation before final admission.

## Slice plan

### S1 — Browser contracts and immutable profiles

Define IDs, profile/target contracts, finite limits, page/session/element/result models, safe errors,
configuration, deterministic serialization, and omission compatibility. No browser action enters the
authority catalog yet and no remote effect occurs.

### S2 — Adapter boundary and deterministic browser

Define `BrowserAdapter`, zero-effect prepare/commit contracts, deterministic fake page state, opaque
element identity, page revisions, JavaScript/subresource blocking contracts, and deterministic
network-admission interfaces. No production browser engine is bundled.

### S3 — Canonical browser authority

Add the finite browser actions/resources to the RFC-0033 closed-world catalog. Define exact
`AuthorityIntent` digests, profile/session/page/revision freshness bindings, subject validation, and
cross-boundary non-amplification tests.

### S4 — Sessions, page observation, and stale-safe local mutation

Implement session open/close, one-page lifetime, bounded `browser.page.read`, opaque elements,
`browser.element.fill`, stale-revision rejection, disclosure freshness, and deterministic lifecycle
semantics without remote navigation.

### S5 — Controlled navigation and browser network admission

Implement server-owned initial navigation targets, exact allowed origins, DNS/IP/TLS admission,
finite redirects, zero-effect preparation, final freshness, no-retry/indeterminate semantics, and
blocked automatic navigation/subresource channels.

### S6 — Click effects and agent tool composition

Implement exact stale-safe click plans, link/form intent binding, remote-effect admission, reviewed
`tool.invoke -> browser.*` mediated transitions, server-owned browser tool bindings, final tool
revalidation, and confused-deputy/cross-agent adversarial tests.

### S7 — Runtime lifecycle, observability, administration, and release hardening

Add optional Runtime ownership, bounded shutdown, content-free observations, separately authorized
redacted health/inspection, migration guidance, ADRs, threat-model review, complete targeted tests,
and a dedicated package/release gate.

### S8 — v0.35.0 release finalization

Update version/release metadata only after S1-S7 pass targeted security review, global gates, package
boundary validation, full canonical diff review, and final adversarial security review. Publication,
tagging, remote branch/PR operations, and merge remain separately authorized release operations.

## Compatibility

Phoenix OS v0.34.0 behavior is preserved when browser automation configuration is omitted.

Upgrade creates no browser profile, browser engine, browser process, session, page, cookie, navigation,
permission, approval, tool, worker, listener, network request, host effect, workspace transfer, or
remote effect automatically.

Existing RFC-0034 controlled HTTP behavior, webhook delivery, inference transport, host automation,
workspace handling, memory, and agent execution remain independently authoritative and unchanged.

## Architecture freeze

The v0.35.0 implementation MUST preserve the following frozen boundaries:

- browser content and browser state remain data rather than authority;
- arbitrary URL, selector, coordinate, script, executable, proxy, and host-path control remain absent;
- JavaScript and autonomous/background browser channels remain disabled for v0.35.0;
- one page per session, no downloads/uploads, and no automatic subresources remain fixed scope limits;
- browser, tool, network, host, workspace, memory, and model authority remain independent;
- exact stale-safe session/page/revision/element identity remains mandatory;
- browser-originated remote effects require current destination admission;
- final effect admission occurs after the last attacker-controlled wait with no new untrusted blocking
  wait before commit;
- disclosure uses its own fresh `browser.page.read` authority; and
- no indeterminate remote effect is transparently retried.

Any implementation need that weakens or expands one of these frozen boundaries requires architecture
re-review before code proceeds.
