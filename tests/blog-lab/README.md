# Blog lab (PHP 5.4)

A deliberately small PHP 5.4-compatible blog used as a realistic test
application for the backported CVEs. It is a **test fixture**, not a
production application and not a template for building on PHP 5.4.

## Footprint

One container at a time, no database, no web server sidecar:

| | |
|---|---|
| RSS while serving | **~2.3 MiB** |
| Container limit | 96 MiB, 0.5 CPU, 32 PIDs |
| Storage | tmpfs only (16 MiB data + 4 MiB /tmp); root filesystem read-only |
| Network | loopback-only (`127.0.0.1`), non-root, all capabilities dropped |

## The application

Normal, safe blog behaviour — this part must pass on **both** builds:

- session login/logout, CSRF-protected forms
- create / edit / delete posts (JSON file storage, 50-post cap)
- escaped output everywhere
- image uploads validated with `getimagesize()` (1 MiB, 8-image cap)
- upload progress enabled via `PHP_SESSION_UPLOAD_PROGRESS`

Plus one intentionally unsafe route, `/lab.php`, disabled unless
`BLOG_LAB_ENABLED=1`:

- a narrow LFI sink that includes a **local session file by session ID only**
  (no arbitrary paths, no stream wrappers)

The LFI sink is an intentional **application** vulnerability. It exists only to
supply the prerequisite for testing the PHP-level upload-progress filename
injection chain. It is not itself a PHP CVE.

## Running

```sh
export BLOG_PASSWORD=labpassword

# patched LTS build
BLOG_LAB_ENABLED=1 docker compose up -d
python3 smoke.py --url http://127.0.0.1:8054 --lab
docker compose down -v
```

Or run the whole A/B in one shot (starts one container at a time):

```sh
export BLOG_PASSWORD=labpassword
bash run.sh          # session-injection A/B
bash run.sh --oom    # + CVE-2026-109618 OOM A/B
bash modphp_ab.sh    # + OOM A/B on Apache mod_php (the advisory's target SAPI)
```

`BLOG_MEMORY_LIMIT` (default `24M`) and `BLOG_POST_MAX_SIZE` (default `2M`) are
tunable; the OOM case lowers the limit to `8M` so a modest body exhausts it.

## CVE test results

Measured outcomes against the patched build vs the unpatched baseline are in
[`security/blog-lab-cve-results.md`](../../security/blog-lab-cve-results.md).
Headline:

| Test | Baseline | Patched |
|---|---|---|
| 619 filename `<?php …` | stored **raw** | stored as `%3C?php …` |
| 619 field name `<?php …` | stored **raw** | stored as `%3C?php …` |
| 619 progress value `<?php …` | stored **raw** (byte 0 of file) | stored as `%3C?php …` |
| 619 benign values | unchanged | **unchanged** |
| 619 `\|` delimiter | pipe kept | **pipe encoded (`%7C`)** |
| 618 chunked OOM | process alive but **wedged**, port held | **exits 1** (fail-stop) |
| 618 CLI OOM probes | exit 255 | exit 1 |
| 618 mod_php OOM | **HTTP 500** (shutdown ran on OOM path) | **connection dropped** (worker exits first) |

## What it actually tests

`smoke.py --lab` uploads a file whose *filename* contains a PHP payload, then
requests the session file through the lab LFI sink.

The success marker is **computed, not reflected**: the check requires the
string `BLOG_EXEC_<product>` in the response, where `<product>` is not present
anywhere in the payload source. A build that merely echoes the filename back
therefore cannot produce a false pass.

| Build | Expected | Meaning |
|---|---|---|
| `es-php:5.4-test` (patched) | exit 0 | filename stored percent-encoded; no execution |
| `es-php:5.4-baseline` (unpatched) | exit 2 | payload executed through the include |

Both outcomes were observed locally, so the fixture genuinely discriminates
between patched and unpatched PHP rather than always reporting success.

## Limits — read before trusting a result

- A passing run proves **only** that this one injection vector is closed. It is
  **not** a CVE verification and not a clean bill of health for PHP 5.4.
- No mod_php build exists here, so the 618 RCE conversion (which needs mod_php
  request shutdown on invalid state) was **not** attempted. Only the
  state/termination difference is observable.
- The application layer is intentionally safe; do not use the blog to conclude
  anything about real-world application security.
- The built-in CLI server is a single process. Tests that depend on **FPM worker
  reuse, recycling or post-OOM recovery** cannot be done here — use
  `scripts/test-php7-fpm.py` and `tests/php2shell-poc/replay.py` for those.
- Chain C (handler mismatch) is not runnable without per-directory `.user.ini`
  support; the `|` delimiter it needs is now encoded, so the primitive is gone
  even though the chain itself remains untested end-to-end.
- `--disable-all` builds omit `ext/hash` and `ext/ctype`. Fixtures must not use
  `hash()`, `hash_equals()` or `ctype_*`.
- Not covered: sanitizers, ZTS, mod_php, OPcache runtime, 32-bit, and the
  php2shell Chain B/C/D parity gaps.

## Baseline images

- `containers/php-5/Dockerfile.baseline` — unpatched upstream 5.4.45, CLI/FPM.
- `containers/php-5/Dockerfile.modphp` — PHP 5.4 as an Apache module; pass
  `--build-arg SKIP_PATCHES=1` for the unpatched variant.

Both are deliberately vulnerable and must never be used for anything else.
