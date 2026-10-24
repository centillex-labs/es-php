# Security support policy

This project publishes **LTS (long-term support) source releases** for PHP
branches that upstream has already declared end-of-life. The `-lts<N>` version
suffix is what identifies such a build at runtime:

```
$ php -v
PHP 8.1.34-lts1 (cli) (built: ...)
```

`PHP_VERSION_ID` is deliberately **not** changed, so integer version checks
behave exactly as on a vanilla build of the same upstream release.

## What "LTS" means here

| | |
|---|---|
| **Covered** | Security fixes for vulnerabilities affecting the maintained branches, backported from upstream where a fix exists, adapted where it does not. |
| **Branches** | 5.4.45, 5.5.38, 5.6.40, 7.0.33, 7.1.33, 7.2.34, 7.3.33, 7.4.33, 8.1.34 |
| **Cadence** | Best-effort, on disclosure. No guaranteed response time. |
| **Artifacts** | Source tarballs `php-<release>.tar.gz`, with `SHA256SUMS` and a per-archive `LTS-RELEASE.json` manifest. |

## What "LTS" does **not** mean

- **Not upstream parity.** Bug fixes, features, performance work and
  non-security changes are not backported.
- **Not a complete security audit.** A release means "the listed patches are
  applied", not "this branch is free of unknown vulnerabilities".
- **Not a substitute for upgrading.** EOL branches carry unfixed design-level
  weaknesses that no patch series can remove.
- **Not all changes are security fixes.** The series includes explicitly
  labelled compatibility overrides; see the manifests and
  [`security/upload-progress-compatibility.md`](security/upload-progress-compatibility.md).
- **Not independently reviewed.** Backports to PHP 5.x are semantic ports, not
  mechanical cherry-picks, and are flagged for independent review in
  [`security/php-5-backport-status.md`](security/php-5-backport-status.md).

## Verifying a release

Every archive contains `LTS-RELEASE.json`, which records the upstream URL and
SHA-256, each applied patch with its SHA-256, and the exact `configure` flags
used in CI. CI **compiles every published tarball** and asserts the version
suffix, `PHP_VERSION_ID`, and the upload-progress policy before release.

```sh
sha256sum -c php-8.1.34-lts1.tar.gz.sha256
tar xzf php-8.1.34-lts1.tar.gz
cat php-8.1.34-lts1/LTS-RELEASE.json
```

## Known unverified areas

Recorded honestly rather than implied as covered:

- Full engine test suites, sanitizers/Valgrind, ZTS, mod_php, OPcache runtime
  and 32-bit builds are **not** covered by the current test matrix.
- php2shell Chain B is **not applicable to 5.4** (Valgrind: no UAF, with an
  8.1 control proving the trigger works). Chain C **reproduces on unpatched
  5.4 and is blocked by patch 003**. See
  [`security/chain-b-c-results.md`](security/chain-b-c-results.md).
- CVE-2026-115560 candidate patches are **held and excluded** from default
  releases.

## Reporting a vulnerability

Open a [private security advisory](https://github.com/centillex-labs/es-php/security/advisories/new)
rather than a public issue.
