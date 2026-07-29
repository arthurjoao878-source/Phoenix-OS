$ErrorActionPreference = "Stop"
python -m ruff check .
python -m ruff format --check .
python -m mypy
python -m pytest
python scripts/check_webhook_release.py
python scripts/check_inbound_release.py
python scripts/check_inference_release.py
python scripts/check_agent_release.py
