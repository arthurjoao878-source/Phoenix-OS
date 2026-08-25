# RFC-0034 Secure Network Egress Threat-Model and Security-Invariant Review

## Review method

This release review maps the frozen RFC-0034 threat model and all forty-five
security invariants to executable S1-S7 evidence. The dominant rule is:

> Remote data is data. Network effects require fresh, exact, server-owned authority.

RFC-0033 remains dominant:

> Every protected operation remains dominated by its canonical authority boundary,
> regardless of how that operation is reached.

Effective authority is an intersection of current trusted constraints, never a
union of permissions or historical decisions.

## Trust boundaries

Trusted state includes Phoenix-owned profile/operation identity and generation,
server-owned method/target/limits/header configuration, current structural
subject state, current policy, exact network intent, cancellation/deadline,
exact-version SecretRef leases, reviewed DNS/IP admission, pinned literals,
reviewed transport, and the RFC-0033 closed-world catalog.

Untrusted data includes model output, prompts, tool arguments/results, request
body, DNS answers before admission, remote response data, redirect locations,
prior authorization/profile observations, observability output, health snapshots,
and caller-controlled URL-like text.

## Attacker-controlled waits and final effect boundary

DNS resolution and TCP/TLS connection establishment are attacker-influenceable
blocking waits. A connected pinned session is not bearer authority and writes no
HTTP request bytes. After the final such wait Phoenix revalidates applicable
revocable sources and admits the protected exchange without another untrusted
blocking wait. Observability, audit, Event Bus, logging, metrics, health, and
inspection cannot insert an awaited step into the final admission-to-send window.

## Invariant map

- Invariant 1: Network egress is disabled unless explicitly configured; omission preserves v0.33.0 behavior.
- Invariant 2: Enabling the subsystem grants no permission, credential, request, socket, browser, workspace, host, or tool authority.
- Invariant 3: Every profile uses a stable server-owned NetworkEgressProfileId.
- Invariant 4: Every profile generation is positive and server-owned.
- Invariant 5: Every operation uses a stable server-owned NetworkEgressOperationId.
- Invariant 6: Public requests select only profile and operation IDs and contain no URL.
- Invariant 7: Scheme, host, port, DNS resolver, proxy, TLS, redirect, credential, and literal destination selection remain server-owned.
- Invariant 8: HTTP method and effect classification are reviewed server-owned operation state.
- Invariant 9: Request target is exact server-owned canonical visible-ASCII origin-form.
- Invariant 10: Request body is bounded data and exact-body SHA-256 participates in intent binding.
- Invariant 11: Caller headers are absent; reviewed media and credential-prefix material is validated before transport use.
- Invariant 12: Host, framing, transfer, proxy, forwarding, cookie, and credential headers are not caller-controlled.
- Invariant 13: Optional credential material originates only from an exact-version SecretRef.
- Invariant 14: Plaintext credentials remain outside public contracts and routine telemetry.
- Invariant 15: Hosted remote destinations require verified HTTPS.
- Invariant 16: Plain HTTP exists only for explicitly configured loopback mode.
- Invariant 17: DNS answer count is bounded and every returned address must pass active destination policy.
- Invariant 18: Any rejected DNS answer fails the whole attempt rather than being silently discarded.
- Invariant 19: Connection attempts use only previously admitted literal destination addresses.
- Invariant 20: Hosted TLS validates the canonical configured hostname rather than response-controlled data.
- Invariant 21: Ambient HTTP/environment proxy behavior is ignored.
- Invariant 22: Redirect responses never trigger an automatic second request.
- Invariant 23: CONNECT, TRACE, protocol upgrade, generic WebSocket, and raw-socket authority remain outside v0.34.0.
- Invariant 24: Every protected request requires fresh exact network.http.request authorization.
- Invariant 25: tool.invoke does not imply network.http.request.
- Invariant 26: network.http.request does not imply tool, model, webhook, memory, workspace, host, browser, or other authority.
- Invariant 27: Effective authority remains the intersection of all currently valid constraints.
- Invariant 28: Internal services preserve the original requester and cannot substitute a stronger subject.
- Invariant 29: Current principal/session/agent/run state is revalidated after the final attacker-controlled wait.
- Invariant 30: Current complete profile generation and operation identity are revalidated after the final attacker-controlled wait.
- Invariant 31: DNS/IP destination admission is revalidated whenever an intervening untrusted wait invalidates it.
- Invariant 32: Cancellation and effective deadlines are revalidated before effect admission.
- Invariant 33: No attacker-controlled blocking wait is inserted after final admission without repeating applicable freshness checks.
- Invariant 34: Response status, headers, and body are untrusted data and never authority.
- Invariant 35: Response data cannot manufacture another network request or protected operation.
- Invariant 36: Cookie storage and Set-Cookie exposure remain outside v0.34.0.
- Invariant 37: Request, response, header, DNS-answer, timeout, and concurrency limits are finite.
- Invariant 38: Potentially effectful requests receive no transparent retry after request bytes may have started.
- Invariant 39: Existing webhook and inference canonical authorizers remain independently authoritative.
- Invariant 40: RFC-0034 does not silently reroute webhook or inference transport through network egress.
- Invariant 41: Tool-to-network composition remains explicitly reviewed in the RFC-0033 closed-world catalog.
- Invariant 42: Unknown in-scope network operations fail closed.
- Invariant 43: Observability and inspection remain content-free and exclude destination identity, bodies, status, credentials, headers, DNS/IP/TLS details, secret references, and authority objects.
- Invariant 44: Browser automation and browser-session authority remain outside RFC-0034.
- Invariant 45: Existing Phoenix OS v0.33.0 behavior remains unchanged when network-egress configuration is absent.

## Adversarial release cases

Release-blocking cases include arbitrary URL/host selection, mixed safe/unsafe
DNS answers, DNS rebinding, special-use and transition addresses, ambient proxy
inheritance, redirects, Host/header smuggling, credential disclosure/substitution,
stale profile generation, policy/session revocation during DNS/connect waits,
cancellation/deadline races, confused-deputy and cross-agent substitution, reuse
of prior ALLOW decisions as capabilities, observer-induced waits in the final
critical window, retry after indeterminate remote effect, unexpected packaged
modules, unsafe archive paths, and package smoke that performs real networking.

The dedicated SSRF and observability adversarial suites plus the complete
network-egress regressions are release requirements.

## Package and publication boundary

`python scripts/check_network_egress_release.py` requires the exact reviewed
network-egress module set, relevant agent/authority integration files,
RFC/migration/release/security documents, safe wheel/sdist paths, matching
metadata, rebuilt-sdist wheel, and offline isolated installed smoke behavior.
The smoke validates contracts and closed-world catalog shape only; it performs no
DNS query, socket connection, HTTP exchange, credential lease, or remote effect.

The exact Python 3.12/3.13 CI matrix must pass for the release commit. Annotated
tag creation, tag push, artifact publication, SHA256SUMS, GitHub Release, PR
creation/review, and merge remain separate explicitly authorized operations.

## Residual risks

RFC-0034 cannot make a malicious remote service trustworthy, provide exactly-once
remote effects, revoke bytes already delivered to a remote peer, or sandbox
hostile installed Python code. Explicit trusted allowlisting of private/special
networks intentionally permits the configured destination scope and therefore
requires operator review. Returned content remains untrusted even after valid TLS.

## Release conclusion

RFC-0034 is acceptable for Phoenix OS 0.34.0 only when all forty-five invariants
remain mapped, complete targeted/global suites pass, the dedicated network gate
and package boundaries pass, and the exact Python 3.12/3.13 CI matrix is green.
