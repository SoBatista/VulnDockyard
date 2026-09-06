# Security policy

## Supported versions

Until a later release exists, only `1.0.x` receives controller security fixes.
Lab vulnerabilities are intentionally present and are not controller defects.

## Report privately

Use GitHub private vulnerability reporting for unintended controller defects,
containment bypasses, cleanup ownership errors, provenance mistakes, or unsafe
workflow behavior. Do not include real target data, credentials, or secrets. If
private reporting is unavailable, contact the maintainer through the repository
profile and request a private channel without disclosing the issue.

Please include the controller version, OS/architecture, Docker version, exact
command, sanitized output, expected behavior, and a minimal reproduction.

## Triage boundary

We classify reports as:

1. VulnDockyard adapter defect.
2. Upstream packaging defect.
3. Upstream runtime defect.
4. Expected intentional vulnerability.
5. Obsolete-dependency compatibility issue.
6. Missing or untrusted image.
7. Architecture-specific failure.

Do not publicly demonstrate a controller escape before a coordinated fix is
available. Training vulnerabilities remain documented at taxonomy level, but
normal output deliberately excludes walkthroughs, flags, and detailed solutions.
