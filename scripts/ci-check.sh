#!/usr/bin/env bash
set -euo pipefail

timeout --signal=TERM --kill-after=10s 30s python scripts/check_version.py
timeout --signal=TERM --kill-after=10s 30s ruff format --check src tests scripts
timeout --signal=TERM --kill-after=10s 60s ruff check src tests scripts
timeout --signal=TERM --kill-after=10s 180s mypy src tests scripts
timeout --signal=TERM --kill-after=10s 180s pytest -m 'not docker and not smoke'
timeout --signal=TERM --kill-after=10s 30s python scripts/check_repository.py
timeout --signal=TERM --kill-after=10s 60s python scripts/install_gitleaks.py
timeout --signal=TERM --kill-after=10s 60s python scripts/secret_scan.py
timeout --signal=TERM --kill-after=10s 30s python scripts/check_workflows.py
timeout --signal=TERM --kill-after=10s 60s python scripts/install_actionlint.py
timeout --signal=TERM --kill-after=10s 30s .tools/actionlint -no-color
timeout --signal=TERM --kill-after=10s 360s python scripts/release_artifacts.py

printf 'Deterministic CI gates passed.\n'
