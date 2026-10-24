# PHP 7.x backports — implementation and validation

> Historical initial mitigation results below. **Upload progress is now restored
> in the default series for every branch.** The eight progress failures below no
> longer occur in the release suites. See [current policy and fresh results](upload-progress-compatibility.md).
> The original patches are unchanged; a second compatibility patch overrides disablement.

The PHP 7.0–7.3 branches now have actual local source ports of the combined
109618/109619 mitigation, not just applicability checks. PHP 7.4 retains the
unmodified official backport. All are included in their branch-specific series.
No CVE-2026-115560 candidate is included.

## Provenance and adaptations

Origin: https://github.com/php/php-src/commit/712e60f9edfd03f0960fc4fc3c2c375f42b90aa2

- Each port is a standalone patch against its final upstream release; it does
  not require applying an older branch's patch first.
- Preserve hard-exit OOM handling, allocator/hash overflow failures, request
  state resets, multipart cleanup, and upload-progress disablement.
- 7.3: adapt declaration/include differences and reset handler state in its
  fast executor teardown path. Add missing ZSTR_MAX_LEN definitions and concat
  bounds checks; preserve full-teardown handling on non-fast paths.
- 7.2: adapt the distinct fast-teardown implementation and VM concat handlers.
- 7.0/7.1: these have no corresponding fast-shutdown path. Reset handler stacks,
  exception/error state and object-store pointers at the end of full teardown,
  outside cleanup try blocks so bailout does not skip the final reset. Add
  missing huge-allocation alignment overflow checks and adapt older diagnostics.
- 7.0–7.2: retain the original minimum array capacity rather than import the
  singleton allocation optimization tied to newer hash layouts. The hard-exit
  allocator policy still applies. This is an explicit departure from upstream;
  request-parsing stress/failure review remains necessary.
- Regenerate zend_vm_execute.h using each branch's own zend_vm_gen.php, executed
  with PHP 7.4 inside Docker. Do not transplant generated VM handlers.
- Use `1` rather than `true` in the disabled callback on branches lacking that
  definition. Build legacy branches with `-fcommon` on modern GCC.

## Results

All five baseline archives match php.net SHA-256 metadata. All final patches
apply with --fuzz=0. All release Docker builds include CLI, FPM, session and
OPcache. OPcache compilation is not equivalent to runtime OPcache validation.

Session/serialization PHPT suites:

| Branch | Baseline | Passed | Skipped | XFAIL | Failed |
|---|---|---:|---:|---:|---:|
| 7.4 | 7.4.33 | 354 | 2 | 2 | 8 |
| 7.3 | 7.3.33 | 346 | 3 | 3 | 8 |
| 7.2 | 7.2.34 | 342 | 3 | 3 | 8 |
| 7.1 | 7.1.33 | 326 | 3 | 2 | 8 |
| 7.0 | 7.0.33 | 319 | 3 | 3 | 8 |

The eight failures on each branch are the legacy upload-progress tests: the
combined upstream mitigation disables that feature. No tests were edited or
excluded to conceal this behavior. Scripts retain nonzero suite exit status.

For each local port (7.0–7.3):

- Allocation, unserialization and concatenation OOM probes exit 1 without
  running continuation code or shutdown callbacks.
- CLI and FPM version checks pass.
- A network-isolated, single-worker FPM test reuses the same worker for two
  requests and observes no previous request's handler callback. An OOM request
  kills the worker without a shutdown callback, and FPM replaces it to serve
  the next request successfully. This is a smoke test, not exploit coverage.
- Additional debug builds of 7.0 and 7.3 pass the same probes and have identical
  PHPT summary counts to their release builds. Debug is not ASan or Valgrind.

## Reproduce

```sh
python3 scripts/build-php7.py 7.2
python3 scripts/test-php7.py 7.2       # Nonzero: known upload-progress failures
python3 scripts/test-php7-fpm.py 7.2
python3 scripts/build-php7.py 7.3 --debug
python3 scripts/test-php7.py 7.3 --debug
```

Repeat with any branch 7.0–7.4. Locked archive and patch hashes are verified by
the build script. The generic Dockerfile copies only the selected active patch.
Logs/reports: `work/reports/php-7.*`, with final application checks named
`php-7.x-final-apply.log`. Earlier `*-port.log` files describe intermediate
conflicts, not the final patch. Sources/patches are locked in sources.lock.json.

## Remaining validation

These are local backports with partial validation, not production/security
certification. Full engine suites, ASan/UBSan, Apache mod_php, ZTS, alternate
allocators, OPcache runtime tests and comprehensive CVE-specific failure
sequences remain outstanding. Exact exploit applicability on older unsupported
branches is still recorded as unknown; that is not an assertion of immunity.
Independent code review is particularly important for the relocated shutdown
resets and omitted singleton optimization.
