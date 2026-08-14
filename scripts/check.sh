#!/usr/bin/env sh
set -eu
python -m ruff check .
python -m ruff format --check .
python -m mypy
python -m pytest
python scripts/check_webhook_release.py
python scripts/check_inbound_release.py
python scripts/check_inference_release.py
python scripts/check_agent_release.py
python scripts/check_durable_agent_release.py
python scripts/check_multi_agent_release.py
python scripts/check_agent_memory_release.py
python scripts/check_agent_workspace_release.py
