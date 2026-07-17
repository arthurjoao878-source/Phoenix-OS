# Validation Report

Validated on 2026-07-17 with Python 3.13.5. The project targets Python 3.12+ and CI
covers Python 3.12 and 3.13.

- `ruff check .` — passed
- `ruff format --check .` — passed
- `mypy` in strict mode — passed
- `pytest -q` — 40 passed
- `python examples/event_bus.py` — passed
- `python examples/kernel.py` — passed
- `python -m compileall -q src tests examples` — passed
- wheel build — passed
- isolated wheel smoke test — passed
