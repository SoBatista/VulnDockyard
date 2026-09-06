#!/usr/bin/env bash
set -euo pipefail

python_command="${VDY_PYTHON:-}"
if [[ -z "${python_command}" ]]; then
  if [[ -x .venv/bin/python ]]; then
    python_command='.venv/bin/python'
  else
    python_command='python3'
  fi
fi

exec "${python_command}" scripts/docker_gate.py audit
