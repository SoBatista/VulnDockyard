#!/usr/bin/env bash
set -euo pipefail

overall_timeout="${VDY_SELF_TEST_TIMEOUT_SECONDS:-2700}"
if ! [[ "${overall_timeout}" =~ ^[1-9][0-9]*$ ]]; then
  printf 'VDY_SELF_TEST_TIMEOUT_SECONDS must be a positive integer.\n' >&2
  exit 2
fi
if (( overall_timeout > 3600 )); then
  printf 'VDY_SELF_TEST_TIMEOUT_SECONDS must not exceed 3600 seconds.\n' >&2
  exit 2
fi

python_command="${VDY_PYTHON:-}"
if [[ -z "${python_command}" ]]; then
  if [[ -x .venv/bin/python ]]; then
    python_command='.venv/bin/python'
  else
    python_command='python3'
  fi
fi

exec timeout --signal=TERM --kill-after=30s "${overall_timeout}s" \
  "${python_command}" scripts/self_test.py "$@"
