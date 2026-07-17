#!/usr/bin/env sh
set -eu
ruff check .
ruff format --check .
mypy
pytest
