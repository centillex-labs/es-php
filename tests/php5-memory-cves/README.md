# LTS 2 memory-safety regressions (exif / bcmath / mbstring)

Four upstream reproducers applied to PHP 5.4, 5.5 and 5.6. The rule is the same
as everywhere else in this repository: a case counts only when an **unpatched
baseline fails by the same mechanism the fix removes**. Cases that this platform
cannot exhibit are reported as `UNPROVEN`, never as passes.

| Case | CVE | Evidence | Result |
| --- | --- | --- | --- |
| `mbstring-bug79037` | CVE-2020-7060 | UBSan `-fsanitize=bounds` | **proven on 5.4** |
| `mbstring-bug79037-behaviour` | CVE-2020-7060 | conversion result | **proven on 5.4/5.5/5.6** |
| `bcmath-bug78878` | CVE-2019-11046 | — | unproven |
| `exif-bug79282` | CVE-2020-7064 | — | unproven |
| `exif-bug76423` | CVE-2018-14883 | — | unproven |

## mbstring (CVE-2020-7060) — proven

`mbfl_filt_conv_big5_wchar()` accepted CP950 trail bytes from `0x3a`, which are
not valid CP950 trail bytes. When no `cp950_pua_tbl` row matches, `k` reaches the
table length and the following `cp950_pua_tbl[k][2]` reads **one row past the end
of the table**:

```
/usr/src/php/ext/mbstring/libmbfl/filters/mbfilter_big5.c:201:24:
    runtime error: index 5 out of bounds for type 'short unsigned int [5][4]'
```

The patched build produces no such report. Valgrind cannot see this: the table is
a global array and Memcheck does not model globals, which is why an UBSan image
(`Dockerfile.ubsan`, `Dockerfile.ubsan-baseline`) is used instead. UBSan has no
exit-time scanner, so unlike LeakSanitizer it does not hang the build.

The consequence is also visible without a sanitizer, which is what makes the
5.5/5.6 runs meaningful: the out-of-bounds row is used to compute the output
character, so `"\x81\x3a"` is decoded as `string(3) "脺"` on unpatched builds and
as the correct `string(1) "?"` once the trail-byte range is fixed.

## The three unproven cases

They are patched in the series and documented as **not proven here**:

- **CVE-2019-11046 (bcmath)** — the bug needs a libc whose `isdigit()` accepts
  bytes `>= 0x80`; glibc is ASCII-only, so `bc_str2num()` never leaves the ASCII
  range and no read occurs. The advisory names Windows. Neither Memcheck nor
  UBSan reports anything, on baseline or patched builds.
- **CVE-2020-7064 (exif)** — the upstream report is a MemorySanitizer
  use-of-uninitialized-value. The `itemlen+1` over-allocation keeps the stray
  read *inside* the heap block, so Memcheck stays silent and `-fsanitize=bounds`
  has nothing to index.
- **CVE-2018-14883 (exif)** — requires a 32-bit `size_t` for
  `offset + size` to wrap. On `amd64` the sum cannot wrap, so the documented
  trigger is unreachable and the shipped control image behaves identically.

## Run

```sh
python3 tests/php5-memory-cves/run.py --branch 5.4 --report work/reports/php-5.4-memory-cves.json
python3 tests/php5-memory-cves/run.py --branch 5.6 --only mbstring-bug79037-behaviour ...
```

Images needed: `es-php:<branch>-extras`, `-extras-baseline`, and for the UBSan
case `es-php:<branch>-ubsan`, `-ubsan-baseline`.

Reports: `work/reports/php-<branch>-memory-cves.json`.

## Limits

Only the mbstring case reaches a *memory* verdict, and only on 5.4. 5.5 and 5.6
are proven behaviourally; the source region and the patch are identical in all
three branches, but no UBSan image was built for them. Nothing here is a
weaponised exploit, and no case proves the absence of other bugs in these
extensions.
