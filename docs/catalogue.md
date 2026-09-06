# Initial catalogue review

Research was refreshed from canonical project repositories, official OWASP pages,
official project registries, and upstream automation on 2026-09-06. A container
starting is not adapter verification. Detailed evidence and limitations remain in
each machine manifest.

| Lab | Status | Trust / exact blocker |
|---|---|---|
| OWASP Juice Shop 20.2.0 | runnable | `upstream-pinned`; official release automation, locked multi-arch index, GitHub-hosted amd64 identity/challenge/lifecycle smoke passed with the Docker 28 minimum enforced; no verified image signature. |
| WebGoat/WebWolf 2025.3 | quarantined | Official locked image exists; dual-app registration, WebWolf tools, reset, timezone, and containment smoke remain. |
| OWASP crAPI 1.1.6 | quarantined | Its ten-service deployment mixes version-substituted crAPI images, fixed mutable tags, and `latest`; no complete immutable image set or happy-path verification exists. |
| DVWA | quarantined | Commit image is locked; moving MariaDB, setup/login/module/reset combination is not yet verified. |
| bWAPP 2.2 | quarantined | No official image; official credits reserve all rights, SourceForge names no license, and no explicit redistribution grant was found. |
| Mutillidae II | quarantined | Five official role-tag images need a joint immutable lock, architecture evidence, and database/LDAP functionality smoke; only LDAP uses named volumes. |
| VAmPI | quarantined | Official automation exists; reviewed digest and seeded API smoke are pending. |
| Damn Vulnerable GraphQL Application | quarantined | Maintainer image lacks discoverable publication automation, reviewed digest, and GraphQL smoke. |
| OWASP WrongSecrets 1.13.5 | quarantined | OWASP GHCR automation exists; commit-specific digest, port 8090 MCP service, and core challenge subset smoke are pending. Desktop mode is forbidden. |
| OWASP NodeGoat 1.4 | quarantined | No upstream application image; v1.4 builds on Node 4.4/Node 4 Alpine and uses unresolved `mongo:latest`. |
| OWASP RailsGoat | quarantined | No upstream image; broad source bind, amd64-only build, and missing full-function MySQL/MailCatcher stack. |
| OWASP Security Shepherd 3.1 | quarantined | No upstream image; pinned v3.1 builds web and MySQL from local contexts, declares no named volumes, and needs first-run/TLS/mobile verification. |

The controller's Apache-2.0 license does not relicense any lab. Upstream images are
pulled and cached by Docker, not redistributed by this repository. bWAPP has no
build recipe or published image unless explicit redistribution authority is obtained.
