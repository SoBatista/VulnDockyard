# Contributing

Contributions are welcome for the controller, reviewed adapter metadata, tests,
documentation, and workflows. Never add a vulnerable application's source tree.

## Development

```bash
git clone https://github.com/SoBatista/VulnDockyard.git
cd VulnDockyard
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
pre-commit install
scripts/self-test.sh
```

The complete self-test runs real digest-pinned Docker smoke tests and requires an
available loopback port. Use focused unit commands while iterating; do not mark a
release ready until the complete command passes without required skips.

## Changes and release impact

Use focused Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `ci:`,
`chore:`). Every post-1.0 pull request carries exactly one of
`release:major`, `release:minor`, or `release:patch`, and includes that exact
single SemVer increment plus its reviewed changelog section. Version state is
reviewed in the pull request; no post-merge bump commit is created.

All commits must include a Developer Certificate of Origin sign-off:

```text
Signed-off-by: Your Name <your-email@example.com>
```

Use `git commit -s`. By signing off, you certify the [DCO](DCO.md). Do not submit
secrets, proprietary source, exploit walkthroughs, or registry credentials.

## Adapter changes

Provide canonical upstream evidence, a full OCI digest, publisher-origin evidence,
license/redistribution review, architectures, containment review, expected
functionality tests, reset semantics, and a dated platform verification. Pulling
an image or receiving HTTP 200 is not sufficient. Changes to intentional vulnerable
behavior require explicit review so a training exercise is not accidentally fixed.

PRs require passing checks, resolved conversations, linear history, and maintainer
approval to merge. The project never automerges.

