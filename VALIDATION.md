# Validation — Phoenix OS v0.17.0

RFC-0017 was validated against the complete Phoenix OS regression suite with strict static analysis,
packaging checks, loopback HTTP integration, and Runtime lifecycle coverage.

## Commands

```powershell
python -m pip install -e ".[dev]"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\check.ps1
python -m build
python -m twine check .\dist\*.whl .\dist\*.tar.gz
python .\examples\control_plane_dashboard.py
```

## Results

- Ruff lint passed;
- Ruff formatting check passed for 186 Python files;
- mypy strict passed for 186 source files;
- 688 tests passed;
- wheel and source distribution passed Twine validation;
- wheel contains the packaged dashboard HTML, CSS, JavaScript, and SVG assets;
- package version and plugin compatibility metadata report 0.17.0.

## Validated behavior

- immutable versioned control-plane contracts and explicit serializers;
- omission of job arguments, outputs, contexts, workflow definitions, metadata, audit bodies,
  cryptographic digests, Event Bus payloads, tokens, and secrets;
- loopback-only IPv4 and IPv6 configuration validation;
- hashed administrator token retention and constant-time bearer comparison;
- bounded request, response, connection, page, event-retention, wait, and waiter limits;
- authenticated health, snapshot, jobs, workflows, capabilities, plugins, audit, and event routes;
- deterministic pagination and event cursor ordering;
- retention-gap and dropped-count reporting for slow clients;
- HTTP 429 backpressure and shutdown wake-up for long-poll readers;
- fixed packaged dashboard asset manifest with path-traversal rejection;
- strict Content Security Policy, no-store caching, same-origin, no-referrer, and frame denial;
- no inline or external scripts, styles, fonts, images, CDN dependencies, `innerHTML`, or `eval`;
- browser-tab-only token retention through `sessionStorage`;
- Runtime-owned Event Bus stream and HTTP server startup and reverse shutdown;
- safe empty dashboard sources when jobs or workflows are absent;
- all previously validated kernel, events, capabilities, runtime, configuration, observability,
  state, plugins, policy, identity, secrets, audit, jobs, and workflow behavior.

Phoenix OS v0.17.0 satisfies RFC-0017 while retaining a local, authenticated, read-only boundary.
Remote administration and write operations remain outside the built-in control plane.
