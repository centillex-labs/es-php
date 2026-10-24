# PHP 5.4–5.6 local backports and validation

> Historical initial mitigation results below. **Upload progress is now restored
> in the default series for every branch.** The eight progress failures below no
> longer occur in the release suites. See [current policy and fresh results](upload-progress-compatibility.md).
> Other adaptation details below describe the retained first patch, not the net stack.

## Scope and status

| Branch | Final source release | Source SHA-256 verified | Release/debug Docker builds | Patch application |
|---|---|---|---|---|
| 5.4 | 5.4.45 | Yes, PHP release API | Both succeeded | Zero fuzz |
| 5.5 | 5.5.38 | Yes, PHP release API | Both succeeded | Zero fuzz |
| 5.6 | 5.6.40 | Yes, PHP release API | Both succeeded | Zero fuzz |

These are **local semantic ports**, not official PHP 5 fixes and not independently
CVE-verified. Applicability remains `unknown`, rather than asserting that the
specific modern CVE exploit chains exist on PHP 5. The active patch is stored
once under each branch's CVE-2026-109618 directory and referenced for 109619.
CVE-2026-115560 candidate patches are not included.

The sources come from museum.php.net; their hashes are checked against the
PHP release API and recorded in `sources.lock.json`. Builds extract the locked
tarballs inside Docker, not host scratch trees. PHP 5.4 has no bundled OPcache;
5.5/5.6 builds enable it, but OPcache runtime behavior was not tested. All builds
include CLI, FPM, session and JSON. Modern GCC uses `-fcommon`; old upstream
compiler warnings remain visible. No host compilation was performed.

## Semantic mapping from the PHP 7.4 EOL mitigation

Upstream reference: `712e60f9edfd03f0960fc4fc3c2c375f42b90aa2`.

- **OOM:** replace the PHP 5 allocator's reserve-release / `zend_error_noreturn`
  / bailout route with a fixed-size diagnostic and `_exit(1)`. Do not run PHP
  shutdown functions, user handlers or process exit handlers after allocator
  failure. Convert safe-address overflow paths and Balloc allocation failure
  to the same termination helper. Persistent malloc/realloc failure uses
  `_exit` rather than `exit`. The helper uses PHP 5's TSRMLS and filename APIs.
- **Allocation arithmetic:** guard allocator header/alignment calculations
  before they wrap; hash initialization/resize overflow uses hard termination.
  Keep PHP 5's pointer-bucket layout rather than transplanting PHP 7's arrays.
- **Strings:** PHP 5 uses signed-int lengths rather than zend_string/size_t.
  Check bounds *before* adding lengths in concat, add-char and add-string
  helpers, including the terminating byte. PHP 5 VM opcodes call these helpers;
  there is no PHP 7 FAST_CONCAT implementation to regenerate here.
- **Request teardown:** reset pointer-valued error/exception handlers and their
  stacks, error handling, exception pointer and object-store state at the end
  of executor teardown, outside individual bailout-catching cleanup blocks.
  Null destroyed superglobals and SAPI auth/content-type/current-user pointers;
  reset modules_activated. Reset linked-list head/tail after destruction.
- **Multipart:** retain only Content-Disposition and Content-Type, ignore
  duplicates, use size_t substring lengths, and enforce max_multipart_body_parts.
  Its default is max_input_vars plus max_file_uploads; addition is bounded and
  the counter is checked before decrement. Preserve PHP 5's smart_str and
  TSRMLS APIs rather than copying the PHP 7 interfaces.
- **Upload progress:** return before progress session decoding, even if its INI
  setting is enabled. This is the same deliberate feature restriction as the
  upstream EOL mitigation, not a feature-preserving solution.

PHP 7's singleton-array allocation optimization is **not ported**: PHP 5 has a
fundamentally different HashTable/zval layout. No unsupported-branch OOM model
or newer serializer implementation is transplanted. These differences and the
relocated teardown resets require independent security review.

## Validation results (final patch hashes)

All three branches:

- Release **and debug** CLI/FPM version probes succeeded.
- Release **and debug** allocation, unserialization and concatenation OOM probes
  exited 1 with memory-limit diagnostics, without shutdown/continuation markers.
- Release single-worker FPM tests reused the worker across normal requests,
  did not leak the installed error handler into the next request, and replaced
  the worker following OOM. Tests use an isolated Unix socket, no container network.
- Direct HTTP no-WAF tests passed **13/13 per branch**, with valid fixture JSON,
  exact versions and the same CLI-server PID throughout the adapted suite.
- Original `../block-phpshell/tests/prod_check.py` ran **unchanged**: eight HTTP
  200 / NOT BLOCKED responses, baseline/final GET 200, exit 1 on every branch.
  These are expected failed WAF assertions, not PHP security failures or passes.
- The final HTTP rerun also passed 13/13 on all six previously built PHP 7/8 images.

### Session + serialization PHPT suites

Failures are not suppressed; all six suite runs exit nonzero.

| Branch | Mode | Pass | Skip | Warn (XPASS) | XFAIL | Fail |
|---|---|---:|---:|---:|---:|---:|
| 5.4 | Release | 255 | 5 | 1 | 0 | 8 |
| 5.4 | Debug | 255 | 5 | 0 | 1 | 8 |
| 5.5 | Release | 268 | 5 | 1 | 0 | 8 |
| 5.5 | Debug | 268 | 5 | 0 | 1 | 8 |
| 5.6 | Release | 289 | 7 | 2 | 0 | 8 |
| 5.6 | Debug | 289 | 7 | 0 | 2 | 8 |

The eight failures on every branch are `rfc1867.phpt`, `rfc1867_inter.phpt`, and
`rfc1867_sid_{cookie,get,get_2,invalid,only_cookie,post}.phpt`: they expect upload
progress, which the mitigation disables. The release XPASS / debug XFAIL cases
are bug70172 on all branches and bug69111 additionally on 5.6.

## Reproduce

```sh
python3 scripts/build-php5.py 5.4
python3 scripts/build-php5.py 5.4 --debug
# Historical test script names now accept PHP 5 as well as 7:
python3 scripts/test-php7.py 5.4             # nonzero: retained PHPT failures
python3 scripts/test-php7.py 5.4 --debug     # likewise
python3 scripts/test-php7-fpm.py 5.4
python3 tests/php-lab/test_versions.py 5.4 5.5 5.6
```

Repeat build/suite/FPM commands for 5.5 and 5.6. HTTP test ports are allocated
automatically by Docker on 127.0.0.1, avoiding other local services. Containers
created by these tests are removed afterward.

Reports under ignored `work/reports/`:

- `php-5.*-{test,debug}-build.log`, `*-suite.log`, `*-validation.json`
- `php-5.*-final-apply.log`: dry run against pristine source, zero fuzz
- `php-5.*-fpm.json`: FPM responses and worker logs
- `php-lab-summary.json`: latest selected HTTP matrix, including image IDs
- `php-lab-5.*-prod-check.log`: original WAF-script output
- `php-lab-5.*.log`: CLI-server output

Earlier `*-port.log` / `*-from56.log` record intermediate rejects; final patches
apply cleanly. Scratch reject/original files are excluded by the export script.

## Limits and outstanding review

No full engine suite, ASan/UBSan/Valgrind, 32-bit, ZTS, Windows, alternate
allocator, Apache mod_php, or OPcache runtime validation has been performed.
HTTP shapes are benign and do not force OOM or feed the unserialize sink.
Neither these requests nor the FPM smoke tests reproduce a full CVE exploit.
Fresh unpatched controls were not tested. These changes address a narrow EOL
mitigation, not the many other known PHP 5 vulnerabilities. Do not interpret
successful builds or smoke tests as production-readiness or general security.
