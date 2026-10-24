# Upload progress restored in every default branch

## Policy

At the user's explicit request, preserve session upload progress on **PHP 5.4,
5.5, 5.6, 7.0, 7.1, 7.2, 7.3, 7.4, and 8.1**. Do not use unconditional feature
disablement as this project's default mitigation. The normal
`session.upload_progress.enabled` INI setting still controls the feature.
Compatibility is a goal, not a promise of identical behavior in every application:
other hardening changes, including OOM termination and multipart limits, remain.

Each branch's default series now applies:

1. `CVE-2026-109618/001-avoid-state-corruption.patch` (original combined mitigation)
2. `CVE-2026-109619/002-restore-upload-progress.patch` (compatibility override)

The original patch remains unchanged for provenance. The second patch reverses
only the unconditional callback bypass (and its PHP 5 explanatory comment).
Both patches are hash-locked. Default Dockerfiles explicitly copy/apply both.
The override is **not a replacement security fix**. It restores the branch's
original session implementation; it does not introduce a serializer restriction
or the held 115560 prerequisites. Those candidates remain excluded.

**Real-vector results (after hardening):** a follow-up patch
(`CVE-2026-109619/003-harden-progress-filename.patch`) percent-encodes `<` in
progress filenames, closing the php2shell Chain A RCE path (session file
turns over no PHP open tags) while keeping the feature and INI control.
Chains D/E memory corruption did not reproduce; workers die cleanly on OOM.
Details: [php2shell PoC replay](php2shell-poc-replay.md).

**Current security status: partial mitigation, unverified.** The upstream
upload-progress-disable safeguard is absent. Real-vector/CVE testing is deferred
at the user's request. Passing compatibility tests does not establish resistance
to 109618, 109619, or 115560.

## Fresh validation with progress enabled

All nine release Docker images were rebuilt. Existing debug images for 5.4,
5.5, 5.6, 7.0 and 7.3 were also rebuilt with the same active series.
A source audit confirms that ext/session/session.c matches the pristine branch
source byte-for-byte in all 14 rebuilt images, and the default upload-progress
INI setting is enabled. Audit: `work/reports/upload-progress-enabled-audit.json`.

Release session + serialization PHPT suites:

| PHP | Passed | Skipped | Warn/XPASS | XFAIL | Failed |
|---|---:|---:|---:|---:|---:|
| 5.4.45 | 263 | 5 | 1 | 0 | 0 |
| 5.5.38 | 276 | 5 | 1 | 0 | 0 |
| 5.6.40 | 297 | 7 | 2 | 0 | 0 |
| 7.0.33 | 327 | 3 | 0 | 3 | 0 |
| 7.1.33 | 334 | 3 | 0 | 2 | 0 |
| 7.2.34 | 350 | 3 | 0 | 3 | 0 |
| 7.3.33 | 354 | 3 | 0 | 3 | 0 |
| 7.4.33 | 362 | 2 | 0 | 2 | 0 |
| 8.1.34 | 379 | 2 | 0 | 1 | 0 |

The eight previously failing upload-progress tests pass on every PHP 5/7 branch.
Debug 5.4/5.5/5.6 have the same pass/skip counts, with their release XPASS cases
reported as 1/1/2 XFAIL respectively. Debug 7.0/7.3 match release counts.
**PHP 5.4 debug still exits 1:** its old selected-tests runner matches `FAILED`
inside `XFAILED` (`run-tests.php:833`). The report shows zero unexpected failures
and one existing XFAIL, bug70172. This exit code is retained, not suppressed.

All nine release branches also pass:

- Three OOM probes: allocation, unserialization, concatenation; no PHP shutdown
  or continuation marker runs after the tested OOM termination.
- CLI and FPM version checks.
- 13/13 direct HTTP smoke checks with no WAF, valid JSON and a consistent PID.

The rebuilt debug images pass the same OOM/version probes. Original prod_check.py
still reports NOT BLOCKED / exit 1 without a WAF, as expected. These HTTP shapes
are benign and do not exercise the real exploit vector. Earlier FPM worker-reuse
results in historical reports predate this override; do not treat them as fresh
feature-enabled FPM validation.

## Reports and reruns

- `work/reports/php-<branch>-test-{suite.log,validation.json}`
- `work/reports/php-<branch>-debug-{suite.log,validation.json}` (rebuilt debug branches)
- `work/reports/php-lab-summary.json` and `php-lab-<branch>*.log`
- Previous reports archived under `work/reports/upload-progress-disabled-baseline/`.

```sh
python3 scripts/build-php5.py 5.4
python3 scripts/build-php7.py 7.0
python3 scripts/test-php7.py 5.4   # Historical filename; accepts PHP 5/7/8.1
python3 scripts/test-php7.py 8.1
python3 tests/php-lab/test_versions.py
```

The PHP 8.1 experimental Dockerfile adjusts its patch base before applying its
held prerequisite (which itself restores progress). It remains opt-in and has
not been rebuilt or revalidated as part of this default-policy change.
