# Chain B and Chain C results (PHP 5.4)

Closes the two chains previously recorded as "inconclusive" and "not runnable".
Both now have runnable harnesses with built-in controls, and both give a
definite answer for 5.4.

| Chain | Previously | Now |
|---|---|---|
| **B** — `var_destroy()` reentrancy UAF | inconclusive (exploit failed on symbol lookup) | **not applicable to 5.4** — no UAF |
| **C** — per-directory `.user.ini` handler mismatch | not runnable (no CGI SAPI) | **reproduces on unpatched 5.4, blocked by patch 003** |

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
=== 5.4 (es-php:5.4-debug)
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

The 8.1 control is what makes the 5.4 result meaningful: the same trigger, same
payload, same tool, and the UAF appears. Without it, "0 errors" would be
indistinguishable from a broken test.

**Why 5.4 is unaffected.** In 5.4's `var_unserializer.re`:

- `var_push()` allocates into the `first`/`last` chain, while `var_push_dtor()`
  allocates into a **separate** `first_dtor`/`last_dtor` chain — different
  `emalloc` blocks.
- `var_destroy()` therefore frees the reference chain and the
  deferred-destruction chain independently, so the destructor cannot walk into
  memory that was just released.
- `PHP_FUNCTION(unserialize)` declares `php_unserialize_data_t var_hash` as a
  **fresh local** (`PHP_VAR_UNSERIALIZE_INIT`), so the reentrant
  `unserialize('R:1500;')` from `__destruct` resolves against an empty table.
  That is exactly what the trace shows: `R:1500 resolved to: boolean` on 5.4
  versus `integer` on 8.1, where it read real freed memory.

No patch in this repo touches `var_unserializer.c` or `ext/standard/var.c` for
any branch from 5.4 to 7.4 (`8.1` has 2 hits, in the held serializer
candidates). The 5.4 result is therefore a property of PHP 5.4 itself, not
something the hardening changed.

## Chain C — handler mismatch → object injection

Harness: `tests/chain-c-userini/` (`probe.py`, `run.sh`, `web/{app,api}/`),
image `containers/php-5/Dockerfile.cgi` (php-cgi behind Apache CGI, which is
what gives per-directory `.user.ini` support).

**PHP 5.4 has no `php_serialize` handler** — it was added in 5.5.4, and the
first run failed with `Cannot find serialization handler 'php_serialize'`.
Verified directly:

```
5.4   php available | php_binary available | php_serialize NOT AVAILABLE
5.5   php available | php_binary available | php_serialize available
```

So the chain as originally written is not applicable to 5.4. The 5.4-relevant
mismatch is `php_binary` (writer) versus `php` (reader): the writer emits
`\0key` + serialized data, the reader scans for `|`, and a `|` planted in the
uploaded filename lands inside the blob and becomes the split point.

The proof is computed, not reflected — the injected object's `__destruct`
writes a marker, so a response that merely echoes the payload cannot pass:

```
=== BASELINE unpatched (es-php:5.4-cgi-baseline)
    writer handler : handler=php_binary
    reader handler : handler=php
    stored name    : s:4:"name";s:27:"x|O:13:"
    '|' in session : 1
    MARKER         : DESTRUCT_FIRED -> OBJECT INJECTION CONFIRMED

=== PATCHED (es-php:5.4-cgi)
    writer handler : handler=php_binary
    reader handler : handler=php
    stored name    : s:4:"name";s:29:"x%7CO:13:"
    '|' in session : 0
    MARKER         : absent -> no injection
```

The cause is explicit rather than inferred: the `|` is present on the baseline
and absent after the patch, the handler pair is identical in both runs, and the
only difference is the encoded delimiter.

This also retroactively justifies encoding `|` in patch 003 — at the time the
`|` was added it was a defensive measure for an untestable chain.

## Reproducing

```sh
# Chain B (Valgrind; the 8.1 control proves the trigger works)
bash tests/chain-b-uaf/run.sh

# Chain C (php-cgi + Apache CGI, per-directory .user.ini)
bash tests/chain-c-userini/run.sh
```

Both print the expected outcome at the end. Images:

```sh
docker build -f containers/php-5/Dockerfile.cgi -t es-php:5.4-cgi \
  --build-arg BRANCH=5.4 --build-arg VERSION=5.4.45 \
  --build-arg SHA256=$(python3 -c "import json;print(json.load(open('sources.lock.json'))['branches']['5.4']['sha256'])") .
# add --build-arg SKIP_PATCHES=1 and -t es-php:5.4-cgi-baseline for the baseline
```

## Remaining limits

- Chain C was demonstrated for the `php_binary`/`php` pair only. The
  `php_serialize`/`php` pair cannot be tested on 5.4 because the handler does
  not exist there; it would need a 5.5+ build.
- Chain B's verdict is for direct `unserialize()`. The session-decode path
  (Chain E) is separate and is covered by `tests/php2shell-poc/replay.py`.
- No RCE conversion was attempted in either chain. Chain C demonstrates object
  injection (`__destruct` fired) with a benign marker, which is the primitive
  an exploit would build on, not the exploit itself.
- Still not covered anywhere: full engine suites, ZTS, 32-bit, OPcache runtime.
