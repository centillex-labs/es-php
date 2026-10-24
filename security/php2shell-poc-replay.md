# PHP2Shell PoC replay against es-php images

Replay of the local toolkit at `~/php2shell-scratch/php2shell-poc`
(ikow/php2shell-poc) against every `es-php:<branch>-test` image, in Docker,
without a WAF, **with session upload progress enabled** (user-selected default).
Harness: `tests/php2shell-poc/replay.py`. Raw data: `work/reports/php2shell-poc-replay.json`.

Benign proof commands only (`id`/`uname`), in disposable local containers.
This is authorized testing of this project's own images.

## Environment and applicability

Images serve the toolkit's own webroot through the CLI built-in server
(single shared process = same-worker guarantee), with the toolkit's php.ini
values: `memory_limit=32M`, `post_max_size=128M`, `upload_progress` on,
`use_strict_mode=0`, `save_path=/tmp/sessions`. The webroot copy gets a
PHP-5-compatible `vuln.php` LFI sink (`??` is PHP 7+ syntax); that is a fixture
fix, not an exploit change.

- **A** (session injection → LFI): fully applicable; the webroot provides the
  required LFI sink.
- **B** (var_destroy UAF → RCE): CLI exploit inside the container; reported
  `[-] symbols not found` on every image, so the overwrite never executed.
  Treated as **inconclusive**, not a pass.
- **C** (per-directory handler mismatch): **not runnable**; the CLI server has
  no per-directory `.user.ini` support.
- **D** (OOM corruption, mod_php): mod_php is absent; OOM strategies were fired
  against the CLI server instead (see limits).
- **E** (FPM stale BG → UAF): adapted over direct FastCGI to a single-worker
  FPM, using the chain's own producer/consumer strategy.

## History: first replay (before hardening)

With plain feature restore, **Chain A achieved RCE on every branch**
(`[+] RCE CONFIRMED: uid=0(root)`): the raw `<?php …?>` upload filename was
stored verbatim in the session file, and the LFI sink executed it.

## Hardening: 003-harden-progress-record.patch

Applied to every default series after a debugging pass:

- The vector is the raw values stored in the session progress record at
  `MULTIPART_EVENT_FILE_START` (`session.c`). Three strings are attacker
  controlled: the session key suffix (the `PHP_SESSION_UPLOAD_PROGRESS` field
  value), the per-file `field_name`, and the per-file `name` (filename). The
  fix percent-encodes **`<` and `|`** (plus NUL) in the stored copies
  (`php_session_rfc1867_safe_str()`); benign values stay byte-identical.
- Debugging was byte-level (no rr needed — deterministic data flow): `od -c`
  of session files confirmed `%3C?php` replaces `<?php` in the file.
- **Toolkit false positive:** the exploit still printed `RCE CONFIRMED`, but
  the "command output" was literally the text `'; system('id'); echo '` — the
  encoded payload **echoed as plain text**, not executed. The toolkit's marker
  check (`___START___` present) cannot distinguish execution from echo. The
  harness now requires real `uid=` output; with that, Chain A is **blocked on
  all nine branches** (session files contain no PHP open tags).
- Debug builds caught a real bug in my first attempt: unguarded
  `efree(NULL)` tripped PHP 5's debug allocator (`Block 0x00000000 status:
  NULL`, failing `rfc1867_sid_invalid.phpt` on 5.4/5.5/5.6 debug). Fixed with a
  NULL guard; the test now passes everywhere.
- A new PHPT (`rfc1867_progress_encoding.phpt`) ships in each patch and runs
  in the standard suites; it asserts all three fields are encoded and that
  benign values are unchanged.

## Final results (hardened default series, all nine branches)

| Check | Result |
|---|---|
| Chain A true RCE (requires `uid=` output) | **Blocked** on all 9 |
| Chain A toolkit verdict (naive markers) | still prints RCE CONFIRMED (false positive, text echo) |
| Session file contents | encoded (`%3C`, `%7C`), no `<?php` bytes |
| Chain B | inconclusive (symbol lookup fails on these builds) |
| Chain E (adapted FPM) | producer worker terminated on decode OOM; consumer on fresh worker; pool recovered; no stale-state markers |
| Post-OOM HTTP | server healthy or cleanly dead; never corrupted-state |
| PHPT suites (session+serialize) | exit 0, zero failures, new test PASS, all 9 |
| OOM probes + FPM reuse/replacement | pass, all 9 |
| 13-check HTTP matrix | pass, all 9 |

## Interpretation and limits

The injection vector that made Chain A work is closed while the feature (and
normal INI control) is preserved. This does **not** fix application-level LFI
in general: an app that includes any other attacker-influenced file, or writes
attacker data into its own session, remains exposed. Applications that read
progress filenames and cannot tolerate percent-encoding of `<` (rare) must
decode. Chain B/C/D parity gaps above remain open. None of this constitutes a
complete security audit of EOL PHP.

## Reproduce

```sh
python3 tests/php2shell-poc/replay.py            # all nine
python3 tests/php2shell-poc/replay.py 7.4 5.6   # subset
```

Requires `~/php2shell-scratch/php2shell-poc`. Ports are loopback-only and
allocated by Docker; containers are removed after each run.
