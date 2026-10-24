# EOL PHP patch maintenance

Maintained source stacks: PHP **5.4.45, 5.5.38, 5.6.40, 7.0.33, 7.1.33,
7.2.34, 7.3.33, 7.4.33, and 8.1.34**.

## Compatibility policy

**Session upload progress is preserved in every default branch.** A small,
ordered compatibility override reverses the upstream EOL patch's unconditional
feature disablement. The normal PHP INI setting remains effective. The other
hardening changes are retained, so this is not a promise of complete backward
compatibility for every workload.

The override is **not a replacement security fix**. CVE resistance with progress
enabled remains unverified, pending real-vector testing. PHP 5/7/8.1 remain EOL;
these narrow changes do not address all their known vulnerabilities.

Current results and policy: [upload-progress compatibility](security/upload-progress-compatibility.md).
**php2shell PoC replay: Chain A RCE blocked by the progress-record hardening
(in default series); Chain C (handler mismatch) reproduces unpatched and is
blocked by it; Chain B is not applicable to 5.4 (Valgrind, with an 8.1
control); OOM chains did not reproduce.**
Details: [replay report](security/php2shell-poc-replay.md).
The CVE-2026-115560 serializer-policy candidate remains held and excluded from
default builds.

## Releases

Source tarballs are published for every branch as **LTS releases**:

```
php-8.1.34-lts1.tar.gz        # top-level dir: php-8.1.34-lts1/
```

- Version scheme is `<upstream-version>-lts<N>` (e.g. `8.1.34-lts1`);
  `PHP_VERSION_ID` is left at the upstream value so integer checks are
  unaffected.
- Each archive carries `LTS-RELEASE.json` (upstream URL + SHA-256, per-patch
  SHA-256, the exact `configure` flags) and the applied patches in
  `lts-patches/`. Held candidates are never shipped.
- CI **compiles every published tarball** and asserts the version suffix,
  `PHP_VERSION_ID`, and the upload-progress policy before release.

See [RELEASING.md](RELEASING.md) for the release process and
[SECURITY.md](SECURITY.md) for what the `lts` label does and does not promise.

## Layout

- `downloads/`: verified original tarballs (ignored).
- `php-<branch>/`: pristine source extraction (ignored).
- `php-<branch>-patches/series`: authoritative ordered patch stack.
- `sources.lock.json`: source provenance, `es_revision`, and SHA-256 hashes.
- `scripts/es-release.py`: builds publishable LTS tarballs.
- `scripts/verify-release-tarball.sh`: compiles and validates a release.
- `scripts/check-consistency.py`: offline lock/series/hash check.
- `tests/blog-lab/`: tiny PHP 5.4 blog fixture + patched/unpatched A/B runner.
- `security/cves/`: per-CVE tracking.
- `containers/`: Docker development build/test images.
- `work/reports/`: local logs (ignored).

The combined 109618/109619 mitigation is stored once under 109618. The
upload-progress compatibility override is stored under 109619 and applied
second. No duplicate application of the combined patch.

## Docker build and tests

```sh
python3 scripts/check-consistency.py
python3 scripts/es-release.py --list
python3 scripts/es-release.py --all --out dist --cache downloads
bash scripts/verify-release-tarball.sh dist/php-8.1.34-lts1.tar.gz

python3 scripts/build-php5.py 5.4   # also 5.5, 5.6; optional --debug
python3 scripts/build-php7.py 7.0   # also 7.1–7.4; optional --debug
bash scripts/test-php-8.1
python3 scripts/test-php7.py 5.4   # historical name; accepts PHP 5/7/8.1
python3 tests/php-lab/test_versions.py
```

Tarballs must already exist under downloads; URLs and published checksums are
in sources.lock.json. Builds use a fresh extraction inside Docker, not host
scratch trees. PHP 5 includes JSON/session/CLI/FPM; bundled OPcache exists only
from 5.5 onward. PHP 7/8 builds include OPcache; PHP 8.1 also includes zend_test.

## Blog lab

`tests/blog-lab/` is a small PHP 5.4-compatible blog used as a realistic test
application (~2.3 MiB RSS, no database, loopback-only, tmpfs storage):

```sh
export BLOG_PASSWORD=labpassword
bash tests/blog-lab/run.sh          # smoke A/B (safe)
bash tests/blog-lab/run.sh --oom    # + OOM A/B (CVE-2026-109618)
```

Chain B and Chain C harnesses: `bash tests/chain-b-uaf/run.sh`,
`bash tests/chain-c-userini/run.sh`.

The unpatched baseline for differential testing comes from
`containers/php-5/Dockerfile.baseline` (deliberately vulnerable; local use
only). Results, including what they do **not** establish, are recorded in
[security/blog-lab-cve-results.md](security/blog-lab-cve-results.md).

Direct HTTP tests expose randomly allocated **127.0.0.1-only** ports, with no
WAF. CLI/PHPT tests use network-disabled containers. These are development
images, not production runtime images. Debian tags and apt packages are not
pinned, so builds are not hermetic or bit-for-bit reproducible.

## Historical port notes

- [PHP 5 semantic mapping and pre-override results](security/php-5-backport-status.md)
- [PHP 7 semantic mapping and pre-override results](security/php-7-backport-status.md)

Those records describe the initial upload-progress-disabled mitigation. The
current enabled-policy results supersede their test summaries. Full engine,
sanitizer, alternate-allocator, ZTS, mod_php and real-vector validation remain
outstanding.
