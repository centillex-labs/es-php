# CVE-2019-11043 FPM regression (PHP 5.4 / 5.5 / 5.6)

Tests the FastCGI `PATH_INFO` underflow fixed upstream in
`ab061f95ca966731b1c84cf5b7b20155c0a1c06a`.

## What it checks

A single-worker FPM instance serves `worker.php`, which returns a JSON document
containing a computed marker (`137 * 149`), its PID, and `$_SERVER['PATH_INFO']`.
The test sends direct FastCGI requests, so no HTTP server or WAF is involved.

| Case | `SCRIPT_FILENAME` | supplied `PATH_INFO` | expected result |
| --- | --- | --- | --- |
| `normal-path` | script + `/hello` | `/hello` | `/hello` |
| `empty-underflow` | script + 35 `A`s | `` (empty) | `` (empty string) |
| `short-underflow` | script + 35 `A`s | `/x` | `/x` |

The two underflow cases make the vulnerable code compute
`env_path_info + pilen - slen` with `pilen < slen`, so the pointer lands before
the buffer. A following request must reuse the same PID, proving the worker was
not corrupted or replaced by the probe.

## Pass criteria

- **Patched** (`es-php:<branch>-test`): all three cases return the marker, the
  expected `PATH_INFO`, the same PID, and no FPM stderr.
- **Unpatched control** (`es-php:<branch>-baseline`): the `normal-path` case
  passes, and at least one underflow case returns a wrong or missing
  `PATH_INFO`. A control that fails the normal case is treated as a broken
  harness, never as evidence.

## Run

```sh
tests/fpm-path-info/run.sh            # 5.4 5.5 5.6
tests/fpm-path-info/run.sh 5.6
```

Reports: `work/reports/php-<branch>-fpm-path-info-{fixed,baseline}.json`.

## Observed results

| Branch | Patched `empty-underflow` | Unpatched control `empty-underflow` / `short-underflow` |
| --- | --- | --- |
| 5.4 | `""` | `null` (unset) / `""` |
| 5.5 | `""` | `null` (unset) / `""` |
| 5.6 | `""` | `"P{"` (adjacent memory) / `""` |

The 5.6 result is the clearest evidence of the out-of-bounds read: memory in
front of the buffer is surfaced as `PATH_INFO`.

## Limits

This is a behavioral differential, not a Valgrind/ASan memory report, and it is
not the RCE chain. It shows the underflow read is gone and normal routing still
works; it does not prove a complete fix against every `fix_pathinfo` deployment
shape. `cgi.fix_pathinfo=1` is pinned inside the test pool config.
