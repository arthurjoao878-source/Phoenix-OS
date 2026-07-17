$ErrorActionPreference = "Stop"
ruff check .
ruff format --check .
mypy
pytest
