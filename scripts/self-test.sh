#!/usr/bin/env bash
set -euo pipefail

overall_timeout="${VDY_SELF_TEST_TIMEOUT_SECONDS:-2700}"
if ! [[ "${overall_timeout}" =~ ^[1-9][0-9]*$ ]]; then
  printf 'VDY_SELF_TEST_TIMEOUT_SECONDS must be a positive integer.\n' >&2
  exit 2
fi

exec timeout --signal=TERM --kill-after=30s "${overall_timeout}s" \
  python scripts/self_test.py "$@"
