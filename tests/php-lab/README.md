# Direct-to-PHP tests using the block-phpshell lab

Default images now preserve session upload progress on all nine branches.
See [current compatibility results](../../security/upload-progress-compatibility.md).
Smoke-test success is not exploit verification.

Run from the repository root:

```sh
python3 tests/php-lab/test_versions.py
# Or select branches:
python3 tests/php-lab/test_versions.py 7.0 7.4 8.1
```

Requires Docker and the patched `es-php:<branch>-test` images. PHP 7 images need
`--enable-json` (now present in the generic and branch-specific Dockerfiles).
For example, rebuild with `python3 scripts/build-php7.py 7.2`.

## Origin and execution

The user's script is `../block-phpshell/tests/prod_check.py`, not testprod.py.
The runner executes that script **unchanged** against each local container
when available, records its hash/output/exit code, and also runs an adapted
no-WAF suite using its eight benign probe shapes. The sibling project is not
modified. `web/index.php` is adapted from that project's `lab/index.php`, with
a getallheaders polyfill for older CLI-server SAPIs.

Each container runs the PHP CLI built-in server directly, with no reverse
proxy or WAF. Docker allocates free ports, published on 127.0.0.1 only. Containers
have memory/PID limits, mount the fixture read-only, and are removed after
each run. Docker's bridge is used for host connectivity; this does not impose
an outbound-network deny policy. No 115560 candidate image is used.

## Expectations

Original prod_check.py expects Aegis-specific 403/413 responses. It therefore
exits **1** without a WAF, reporting NOT BLOCKED. This is expected and is kept
separate from the PHP smoke-test verdict; the original script is not changed
to claim a WAF pass.

The no-WAF suite requires valid JSON from the expected exact PHP version and
CLI-server SAPI, with the same non-null worker PID for all JSON responses.
HTTP 200 with a PHP fatal-error page, HTTP 403, wrong versions, missing PIDs,
and worker changes do not count as passes. `/fatal` deliberately returns HTTP
500; it does not raise a PHP fatal error. Normal/session responses must remain
healthy afterwards.

13 checks per branch: baseline, explicit HTTP 500, session start, eight probe
shapes, session follow-up, final GET.

## Recorded results

| Branch | Exact version | No-WAF checks | Same worker | Original WAF check |
|---|---|---:|---|---|
| 8.1 | 8.1.34 | 13/13 | Yes | Exit 1, NOT BLOCKED |
| 7.4 | 7.4.33 | 13/13 | Yes | Exit 1, NOT BLOCKED |
| 7.3 | 7.3.33 | 13/13 | Yes | Exit 1, NOT BLOCKED |
| 7.2 | 7.2.34 | 13/13 | Yes | Exit 1, NOT BLOCKED |
| 7.1 | 7.1.33 | 13/13 | Yes | Exit 1, NOT BLOCKED |
| 7.0 | 7.0.33 | 13/13 | Yes | Exit 1, NOT BLOCKED |
| 5.6 | 5.6.40 | 13/13 | Yes | Exit 1, NOT BLOCKED |
| 5.5 | 5.5.38 | 13/13 | Yes | Exit 1, NOT BLOCKED |
| 5.4 | 5.4.45 | 13/13 | Yes | Exit 1, NOT BLOCKED |

Raw reports under `work/reports/` (ignored):

- `php-lab-summary.json`: per-request outcomes, exact versions and image IDs.
- `php-lab-<branch>-prod-check.log`: unchanged user-script output.
- `php-lab-<branch>.log`: PHP container logs, including parser warnings.

## Limits

These are benign request-shape and availability checks, NOT exploit tests.
The serialized-looking form field is sent to the normal fixture route, not
its unserialize sink. The progress-field probe alone does not establish that
progress state was written. The runs do not force OOM, exercise arbitrary
memory corruption, or prove the absence of stale state. They cannot establish
that an unpatched runtime would fail or that the CVEs are fully fixed.
No optional `--size`/chunked probe, mod_php, FPM HTTP path, sanitizer, or ZTS
coverage is supplied by this suite. Separate OOM/FPM tests remain under scripts/.
