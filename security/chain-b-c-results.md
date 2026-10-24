# Chain B and Chain C results (PHP 5.4, 5.5, 5.6)

Closes the two chains previously recorded as "inconclusive" and "not runnable".
Both now have runnable harnesses with built-in controls, and both give a
definite answer for all three PHP 5 branches.

| Chain | Previously | Now |
|---|---|---|
| **B** — `var_destroy()` reentrancy UAF | inconclusive (exploit failed on symbol lookup) | **not applicable to 5.4/5.5/5.6** — no UAF |
| **C** — per-directory `.user.ini` handler mismatch | not runnable (no CGI SAPI) | **reproduces on unpatched 5.4/5.5/5.6, blocked by patch 003** |

## Summary

| Branch | Chain B | Chain C (unpatched) | Chain C (patched) | Handler pair |
|---|---|---|---|---|
| 5.4 | 0 errors | injection confirmed | blocked | `php_binary` → `php` |
| 5.5 | 0 errors | injection confirmed | blocked | `php_serialize` → `php` |
| 5.6 | 0 errors | injection confirmed | blocked | `php_serialize` → `php` |
| 8.1 (control) | **3 invalid reads** | — | — | — |

## Chain B — `var_destroy()` reentrancy UAF

Harness: `tests/chain-b-uaf/` (`trigger_uaf.php`, `run.sh`).

**Why Valgrind and not ASan.** `containers/php-5/Dockerfile.asan` exists, but
PHP's `configure` runs ASan-instrumented `conftest` binaries, and
LeakSanitizer's exit-time scan hangs under the build sandbox — the build never
completes (observed: a `conftest` pinned at 100% CPU for minutes, no progress).
Setting `ASAN_OPTIONS=detect_leaks=0` for the build is the documented fix and is
now in the Dockerfile, but Valgrind reaches the same verdict without a rebuild,
so it is the default harness.

```
=== 5.4 / 5.5 / 5.6 (es-php:<branch>-debug)
    [*] __destruct fired (reentering unserialize)
    [*] R:1500 resolved to: boolean
    ERROR SUMMARY: 0 errors from 0 contexts
=== 8.1-control (es-php:8.1-serializer-debug)
    [*] __destruct fired (reentering unserialize)
    Invalid read of size 8
       at var_access (var_unserializer.re:242)
       by var_destroy (var_unserializer.re:261)
    [*] R:1500 resolved to: integer
    ERROR SUMMARY: 3 errors from 3 contexts
```

The 8.1 control is what makes the 5.x result meaningful: the same trigger, same
payload, same tool, and the UAF appears. Without it, "0 errors" would be
indistinguishable from a broken test.

**Why 5.x is unaffected.** In the 5.x `var_unserializer.re`:

- `var_push()` allocates into the `first`/`last` chain, while `var_push_dtor()`
  allocates into a **separate** `first_dtor`/`last_dtor` chain — different
  `emalloc` blocks.
- `var_destroy()` therefore frees the reference chain and the
  deferred-destruction chain independently, so the destructor cannot walk into
  memory that was just released.
- `PHP_FUNCTION(unserialize)` declares `php_unserialize_data_t var_hash` as a
  **fresh local** (`PHP_VAR_UNSERIALIZE_INIT`), so the reentrant
  `unserialize('R:1500;')` from `__destruct` resolves against an empty table.
  That is exactly what the trace shows: `R:1500 resolved to: boolean` on 5.x
  versus `integer` on 8.1, where it read real freed memory.

No patch in this repo touches `var_unserializer.c` or `ext/standard/var.c` for
any branch from 5.4 to 7.4 (`8.1` has 2 hits, in the held serializer
candidates). The 5.x result is therefore a property of PHP 5 itself, not
something the hardening changed.

## Chain C — handler mismatch → object injection

Harness: `tests/chain-c-userini/` (`probe.py`, `run.sh`, `web/{app,api}/`),
image `containers/php-5/Dockerfile.cgi` (php-cgi behind Apache CGI, which is
what gives per-directory `.user.ini` support).

The writer handler depends on the branch, because **`php_serialize` does not
exist in PHP 5.4** — it was added in 5.5.4. Verified directly:

```
5.4   php available | php_binary available | php_serialize NOT AVAILABLE
5.5   php available | php_binary available | php_serialize available
```

So 5.5 and 5.6 exercise the chain **as originally described**
(`php_serialize` writer → `php` reader), while 5.4 uses the closest available
equivalent (`php_binary` writer → `php` reader). The reader is always `php`,
and in both cases it scans for `|`; a `|` planted in the uploaded filename
lands inside the session blob and becomes the split point.

`run.sh` takes the branch and writes the matching `.user.ini` pair into a
temporary webroot, so the same harness covers both cases.

The proof is computed, not reflected — the injected object's `__destruct`
writes a marker, so a response that merely echoes the payload cannot pass:

```
=== 5.4 BASELINE   writer=php_binary    stored name s:27:"x|O:13:"    1 pipe   MARKER DESTRUCT_FIRED
=== 5.4 PATCHED    writer=php_binary    stored name s:29:"x%7CO:13:"   0 pipes  MARKER absent
=== 5.5 BASELINE   writer=php_serialize stored name s:27:"x|O:13:"    1 pipe   MARKER DESTRUCT_FIRED
=== 5.5 PATCHED    writer=php_serialize stored name s:29:"x%7CO:13:"   0 pipes  MARKER absent
=== 5.6 BASELINE   writer=php_serialize stored name s:27:"x|O:13:"    1 pipe   MARKER DESTRUCT_FIRED
=== 5.6 PATCHED    writer=php_serialize stored name s:29:"x%7CO:13:"   0 pipes  MARKER absent
```

The cause is explicit rather than inferred: the `|` is present on every
baseline and absent after the patch, the handler pair is identical within each
branch, and the only difference is the encoded delimiter.

This also retroactively justifies encoding `|` in patch 003 — at the time the
`|` was added it was a defensive measure for an untestable chain.

## Reproducing

```sh
# Chain B (Valgrind; the 8.1 control proves the trigger works)
bash tests/chain-b-uaf/run.sh es-php:5.4-debug:5.4 es-php:5.5-debug:5.5 \
                              es-php:5.6-debug:5.6 es-php:8.1-serializer-debug:8.1-control

# Chain C (php-cgi + Apache CGI, per-directory .user.ini)
bash tests/chain-c-userini/run.sh 5.4
bash tests/chain-c-userini/run.sh 5.5
bash tests/chain-c-userini/run.sh 5.6
```

Images:

```sh
docker build -f containers/php-5/Dockerfile.cgi -t es-php:<branch>-cgi \
  --build-arg BRANCH=<branch> --build-arg VERSION=<ver> \
  --build-arg SHA256=$(python3 -c "import json;print(json.load(open('sources.lock.json'))['branches']['<branch>']['sha256'])") .
# add --build-arg SKIP_PATCHES=1 and -t es-php:<branch>-cgi-baseline for the baseline
```

## Remaining limits

- Chain C was demonstrated for `php_binary`/`php` (5.4) and
  `php_serialize`/`php` (5.5, 5.6) only. Other handler pairings were not tested.
- Chain B's verdict is for direct `unserialize()`. The session-decode path
  (Chain E) is separate and is covered by `tests/php2shell-poc/replay.py`.
- No RCE conversion was attempted in either chain. Chain C demonstrates object
  injection (`__destruct` fired) with a benign marker, which is the primitive
  an exploit would build on, not the exploit itself.
- Still not covered anywhere: full engine suites, ZTS, 32-bit, OPcache runtime.
