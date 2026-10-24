# Upload-progress encoding scope

Pins down the **boundary** of patch 003, not just the encoding. The patch
percent-encodes `<`, `|` and NUL in the upload-progress record; this test
records exactly where that stops.

```
bash run.sh 5.4      # or 5.5, 5.6
```

## What it asserts

| Field | Expected | Why |
|---|---|---|
| `$_FILES['f']['name']` | **raw** `a<b>c|d.txt` | patch 003 touches the progress record only; the real upload must be untouched |
| `$_SESSION` progress key | `upload_progress_p%3C1` | `<` in the progress name would let the key carry a serializer delimiter |
| `files[i]['name']` | `a%3Cb>c%7Cd.txt` | `<` and `|` encoded, **`>` preserved** |
| `files[i]['field_name']` | `f%3C2` | same treatment |
| session file on disk | no raw `<`, no raw hostile filename | so the file cannot open a PHP tag |

## Why `>` is not encoded

No PHP tag opens with `>` — every form begins with `<` (`<?php`, `<?=`, `<?`,
`<script language="php">`, `<%`). A closing `?>` is inert without an opening
tag, so once `<` is gone there is nothing for `>` to close. Encoding it would
mutate legal Unix filenames (`report>final.txt`) for no security gain, and every
encoded byte is visible to user code in `$_SESSION[...]['name']`.

## Why it runs against the baseline too

A scope test that passes on both builds proves nothing. The baseline run
asserts the **pre-patch** values and requires the raw bytes to still be present,
so it fails loudly if the patch ever leaks into the baseline image. The
negative control was verified by running the `patched` expectations against the
unpatched image, which fails on all four checks.

## Notes

- `|` is **not** forbidden in the session file: it is the `php` serializer's own
  key/value delimiter (`upload_progress_...|a:5:{...}`), so the file always
  contains one. That the attacker's `|` is neutralised is asserted by the
  `progress_files` equality check instead.
- The two runs use **different session IDs** and the session directory is wiped
  between them. Sharing either would let the patched run's already-encoded
  session file leak into the baseline run and mask a regression — this actually
  happened during development and is why the wipe is there.
- Uses the CLI server: the behaviour under test is the session write path, which
  is SAPI-independent, so no Apache/CGI indirection is needed.
