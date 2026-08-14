$ErrorActionPreference = "Stop"

python -m ruff check .
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

python -m ruff format --check .
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

python -m mypy
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

python -m pytest
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

python scripts/check_webhook_release.py
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

python scripts/check_inbound_release.py
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

python scripts/check_inference_release.py
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

python scripts/check_agent_release.py
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

python scripts/check_durable_agent_release.py
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

python scripts/check_multi_agent_release.py
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

python scripts/check_agent_memory_release.py
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

python scripts/check_agent_workspace_release.py
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
