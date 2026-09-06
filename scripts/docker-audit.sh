#!/usr/bin/env bash
set -euo pipefail

label='label=org.vulndockyard.managed=true'
containers="$(docker container ls --all --quiet --filter "${label}")"
networks="$(docker network ls --quiet --filter "${label}")"
volumes="$(docker volume ls --quiet --filter "${label}")"

if [[ -n "${containers}" || -n "${networks}" || -n "${volumes}" ]]; then
  printf 'Residual VulnDockyard resources detected.\ncontainers=%s\nnetworks=%s\nvolumes=%s\n' \
    "${containers}" "${networks}" "${volumes}" >&2
  exit 1
fi

printf 'No managed containers, networks, or volumes remain.\n'
