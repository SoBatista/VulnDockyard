#!/usr/bin/env bash
set -euo pipefail

if [[ -x .venv/bin/python ]]; then
    VDY_PYTHON=.venv/bin/python
elif [[ -n "${VIRTUAL_ENV:-}" && -x "${VIRTUAL_ENV}/bin/python" ]]; then
    VDY_PYTHON="${VIRTUAL_ENV}/bin/python"
elif command -v python3 >/dev/null 2>&1; then
    VDY_PYTHON=python3
else
    printf 'Python 3.11 or newer is required.\n' >&2
    exit 127
fi

timeout --signal=TERM --kill-after=10s 30s "${VDY_PYTHON}" scripts/check_version.py
timeout --signal=TERM --kill-after=10s 30s "${VDY_PYTHON}" scripts/check_environment.py
timeout --signal=TERM --kill-after=10s 30s "${VDY_PYTHON}" -m ruff format --check src tests scripts
timeout --signal=TERM --kill-after=10s 60s "${VDY_PYTHON}" -m ruff check src tests scripts
timeout --signal=TERM --kill-after=10s 180s "${VDY_PYTHON}" -m mypy src tests scripts
timeout --signal=TERM --kill-after=10s 180s "${VDY_PYTHON}" -m pytest -m 'not docker and not smoke'
timeout --signal=TERM --kill-after=10s 30s "${VDY_PYTHON}" scripts/check_repository.py
timeout --signal=TERM --kill-after=10s 60s "${VDY_PYTHON}" scripts/install_gitleaks.py
timeout --signal=TERM --kill-after=10s 60s "${VDY_PYTHON}" scripts/secret_scan.py
timeout --signal=TERM --kill-after=10s 30s "${VDY_PYTHON}" scripts/check_workflows.py
timeout --signal=TERM --kill-after=10s 60s "${VDY_PYTHON}" scripts/install_actionlint.py
timeout --signal=TERM --kill-after=10s 30s .tools/actionlint -no-color
timeout --signal=TERM --kill-after=10s 360s "${VDY_PYTHON}" scripts/release_artifacts.py

printf 'Deterministic CI gates passed.\n'
