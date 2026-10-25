# PHP 5.x LTS 2 backport work ledger

Status: in progress; no LTS 2 release or production images published.
Scope: PHP 5.4.45, 5.5.38, and 5.6.40. Preserve the published LTS 1 assets
and tag. Keep upload progress enabled. Experimental CVE-2026-115560 patches
remain excluded. Hold production container publication pending this audit.

This is an initial backlog, not an exhaustive CVE inventory. Vendor applicability
is evidence for investigation, not proof that an exact local build is exploitable.
Do not infer immunity from an unsupported branch being absent from a CVE record.

## Work matrix

| CVE | 5.4 | 5.5 | 5.6 | Next gate |
| --- | --- | --- | --- | --- |
| CVE-2016-7124 | Fixed + tested | Fixed + tested | Already fixed upstream (verified) | Baseline control confirms 5.4/5.5 were vulnerable |
| CVE-2018-14883 | Patched, unproven | Patched, unproven | Fixed upstream | 32-bit-only overflow; an amd64 baseline cannot fail |
| CVE-2019-11043 | Fixed + tested | Fixed + tested | Fixed + tested | Enabled in series; Docker FPM differential passes |
| CVE-2019-11046 | Patched, unproven | Patched, unproven | Patched, unproven | Needs a libc where isdigit() accepts bytes >= 0x80 |
| CVE-2020-7060 | Proven (UBSan + behaviour) | Proven (behaviour) | Proven (behaviour) | Out-of-bounds cp950_pua_tbl row is gone |
| CVE-2020-7063 | Not ported | Not ported | Not ported | PharData permission bits; 5.4/5.5 phar code differs from 5.6 |
| CVE-2020-7064 | Patched, unproven | Patched, unproven | Patched, unproven | MSan-only trigger; no Memcheck or UBSan baseline |
| CVE-2020-7066 | Fixed + tested | Fixed + tested | Fixed + tested | Baseline connects and truncates; patched refuses |
| CVE-2020-7067 | Not applicable | Not applicable | Not applicable | EBCDIC-only; these builds are ASCII |

CVE-2016-7479 is not automatically an additional PHP 5 vulnerability: Debian
notes that the property-table flaw affects PHP 7, while related defensive changes
were also applied to PHP 5. Review those changes when investigating unserialization.

## CVE-2019-11043: applied and tested

Source reference:
https://github.com/php/php-src/commit/ab061f95ca966731b1c84cf5b7b20155c0a1c06a

All three pristine source trees contain the same unchecked
`env_path_info + pilen - slen` adjustment and unconditional pointer-comparison
`tflag` used by the upstream vulnerable implementation. The candidate ports the
two-line upstream fix verbatim: require `pilen > slen` before pointer adjustment,
and require non-NULL `path_info` before setting `tflag`.

- Generator: `scripts/gen-fpm-path-info-backport.py`.
- Patches: `php-5.{4,5,6}-patches/CVE-2019-11043/001-bound-path-info.patch`.
- All three apply with zero fuzz and are **enabled** in each branch's `series`
  and listed in `sources.lock.json`; `es_revision` moved to 2 for 5.4–5.6.
- Test images rebuilt from scratch and verified: the build log shows
  `patching file sapi/fpm/fpm/fpm_main.c`.
- Regression: `tests/fpm-path-info/` (direct FastCGI, single-worker pool).
  Patched images return the supplied `PATH_INFO` for both underflow shapes;
  unpatched baseline images do not (`null` on 5.4/5.5, `"P{"` — adjacent
  memory — on 5.6). Worker PID is unchanged across every probe.
- Reports: `work/reports/php-5.{4,5,6}-fpm-path-info-{fixed,baseline}.json`.
- Still outstanding for this CVE: no Valgrind/ASan memory report and no
  reproduction of the full exploit chain; the port is only the two-line fix.

## Completion requirements

1. Expand the inventory using upstream changelogs and vendor PHP 5 backports.
   Immediate next items: CVE-2016-7124, CVE-2019-11046, CVE-2020-7060/7063/7064/7066.
2. Resolve applicability per branch, including extension/SAPI/platform conditions.
3. Export minimal CVE-organized patches without modifying pristine source trees.
   Keep generated C and parser sources consistent where applicable.
4. Build and test in Docker only. Security regression tests must demonstrate a
   failing unpatched control and a passing patched result. Avoid weaponized RCE.
5. Add validated patches to branch series and hash lock; preserve existing
   upload-progress, session, OOM, and FPM regression coverage.
6. Bump only the intended branches to LTS 2 via the existing release tooling once
   gates pass. Do not overwrite LTS 1 assets or claim all historical CVEs are fixed.

## Evidence sources

- https://www.php.net/ChangeLog-5.php
- https://security-tracker.debian.org/tracker/CVE-2016-7124
- https://security-tracker.debian.org/tracker/CVE-2016-7479
- https://security-tracker.debian.org/tracker/CVE-2018-14883
- https://security-tracker.debian.org/tracker/CVE-2019-11043
- https://security-tracker.debian.org/tracker/CVE-2019-11046
- https://lists.debian.org/debian-lts-announce/2020/02/msg00030.html
- https://lists.debian.org/debian-lts-announce/2020/03/msg00034.html
- https://security-tracker.debian.org/tracker/CVE-2020-7064
- https://security-tracker.debian.org/tracker/CVE-2020-7066
- https://security-tracker.debian.org/tracker/CVE-2020-7067

## LTS 2 outcome

Ships with a baseline that fails on this platform:

| CVE | 5.4 | 5.5 | 5.6 | Evidence |
| --- | --- | --- | --- | --- |
| CVE-2019-11043 | proven | proven | proven | FastCGI differential, `tests/fpm-path-info/` |
| CVE-2016-7124 | proven | proven | fixed upstream | object type after a failed unserialize |
| CVE-2020-7066 | proven | proven | proven | socket request line is no longer truncated |
| CVE-2020-7060 | proven (UBSan) | proven (behaviour) | proven (behaviour) | `tests/php5-memory-cves/` |

Shipped as hardening but **not proven on `linux/amd64`**, because no baseline can
fail here:

- CVE-2019-11046 — needs a libc whose `isdigit()` accepts bytes >= 0x80.
- CVE-2020-7064 — the trigger is a MemorySanitizer-only uninitialized read.
- CVE-2018-14883 — needs a 32-bit `size_t` for the offset sum to wrap.

Not shipped, still open:

- CVE-2020-7063 (PharData permission bits) — the 5.4/5.5 phar code differs from
  5.6 and no semantic port was attempted.
- CVE-2020-7067 — EBCDIC-only, not applicable to these ASCII builds.
