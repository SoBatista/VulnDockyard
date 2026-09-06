# Command reference

Global `--json` emits deterministic contract version 1 and may appear before or
after a command. `--ground-truth` opts into non-solution verification metadata;
normal output excludes spoilers and flags. Stable exits are: 0 success, 2 usage,
3 not found/ambiguous, 4 policy refusal, 5 preflight, 6 runtime, 7 integrity, and
8 cancelled/interrupted.

| Command | Behavior |
|---|---|
| `help [COMMAND]` | Root or focused help. |
| `version` | Canonical controller version. |
| `doctor` | Python, Engine, Compose, loopback port, hosts, and XDG diagnostics. |
| `list` / `search QUERY` | Reviewed catalogue search; optional synced Vulhub search. |
| `info LAB` / `trust LAB` | Contract details and provenance limits. |
| `pull LAB` | Pull only reviewed `name@sha256` references. |
| `up LAB` / `start LAB` | Idempotent start; default gateway is `127.0.0.1:80`. |
| `status [LAB]` | Requested reference, resolved digest, trust, run ID, and lock match. |
| `verify LAB` | Identity and expected-functionality readiness plus lock match. |
| `open LAB` / `logs LAB` | Open URL or show bounded application logs. |
| `down LAB` / `stop LAB` | Idempotently stop, retain runtime and data. |
| `restart LAB` | Stop/start the same locked deployment. |
| `rebuild LAB` | Recreate with the same lock and preserve declared data. |
| `reset LAB --yes` | Preview, then return owned data to the declared clean state. |
| `remove LAB --yes` | Remove owned runtime resources; retain images. |
| `purge LAB --images --yes` | Remove owned state and optionally exact known digests. |
| `update --check [LAB]` | Read-only stable release discovery. |
| `update [LAB]` | Apply only a reviewed candidate; current release otherwise remains. |
| `hosts add/remove [LAB]` | Preview and atomically edit only the managed block. |
| `provider sync/status vulhub` | Verify/cache or report pinned official metadata. |
| `completion SHELL` | Bash, Zsh, or Fish completion source. |

`--port PORT` is an explicit fallback and stays loopback-only. `--allow-multiple`
acknowledges additional resource use and wider local attack surface. A lab that
declares Internet egress requires `--acknowledge-egress`. An alternate application
image requires both `--unsafe-development` and an immutable `--unsafe-image`; the
run is visibly untrusted and cannot match the reviewed lock.

