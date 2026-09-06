# Initial catalogue review

Research was refreshed from canonical project repositories, official OWASP pages,
official project registries, and upstream automation on 2026-09-06. A container
starting is not adapter verification. Detailed evidence and limitations remain in
each machine manifest.

| Lab | Status | Trust / exact blocker |
|---|---|---|
| OWASP Juice Shop 20.2.0 | runnable | `upstream-pinned`; official release automation, locked multi-arch index, local amd64 identity/challenge/lifecycle smoke passed; no verified image signature. |
| WebGoat/WebWolf 2025.3 | quarantined | Official locked image exists; dual-app registration, WebWolf tools, reset, timezone, and containment smoke remain. |
| OWASP crAPI 1.1.6 | quarantined | Stable release does not map cleanly to its ten moving images; happy path and external challenge limitations remain. |
| DVWA | quarantined | Commit image is locked; moving MariaDB, setup/login/module/reset combination is not yet verified. |
| bWAPP 2.2 | quarantined | No official image; documented CC BY-NC-ND terms leave containerization/modified redistribution unresolved. |
| Mutillidae II | quarantined | Five official components need a joint immutable lock plus database/LDAP functionality smoke. |
| VAmPI | quarantined | Official automation exists; reviewed digest and seeded API smoke are pending. |
| Damn Vulnerable GraphQL Application | quarantined | Maintainer image lacks discoverable publication automation, reviewed digest, and GraphQL smoke. |
| OWASP WrongSecrets 1.13.5 | quarantined | OWASP GHCR automation exists; commit-specific digest and core challenge subset smoke are pending. Desktop mode is forbidden. |
| OWASP NodeGoat 1.4 | quarantined | No upstream image; obsolete mutable Node/Mongo local build. |
| OWASP RailsGoat | quarantined | No upstream image; broad source bind, amd64-only build, and missing full-function MySQL/MailCatcher stack. |
| OWASP Security Shepherd 3.1 | quarantined | No upstream image; generated WAR/database/Mongo builds, first-run setup, TLS, and mobile dependencies. |

The controller's Apache-2.0 license does not relicense any lab. Upstream images are
pulled and cached by Docker, not redistributed by this repository. bWAPP has no
build recipe or published image until explicit redistribution authority exists.

