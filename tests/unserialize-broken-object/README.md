# CVE-2016-7124 (bug #72663) regression

A failed `unserialize()` of an object with nested data used to leave the
partially constructed object alive and reachable through the very reference the
payload created.

## Payload

```php
$inner   = 'a:1:{i:0;O:9:"Exception":2:{s:7:"'."\0".'*'."\0".'file";R:4;}';
$exploit = 'a:2:{i:0;C:3:"obj":'.strlen($inner).':{'.$inner.'}i:1;R:4;}';
```

`obj::unserialize()` recursively decodes `$inner`, which fails mid-way. The outer
array keeps element 1 pointing at the half-built object.

## Marker

The child prints JSON with a computed marker (`137 * 149`) plus the PHP type of
that reference. Nothing in the marker comes from the payload text.

| Build | `ref_type` |
| --- | --- |
| patched | `NULL` |
| unpatched | `object` |

Sanity is required in both directions: the outer value must still be a 2-element
array and the process must exit 0, otherwise the harness reports a broken setup
rather than a pass.

## Results

| Branch | Patched | Baseline | Note |
| --- | --- | --- | --- |
| 5.4 | `NULL` | `object` | patched here |
| 5.5 | `NULL` | `object` | patched here |
| 5.6 | `NULL` | `NULL` | already fixed upstream; baseline is the control |

## Run

```sh
tests/unserialize-broken-object/run.sh
tests/unserialize-broken-object/run.sh 5.4
```

Reports: `work/reports/php-<branch>-unserialize-7124-{fixed,baseline}.json`.

## Limits

Type-of-reference is the observable effect this fix changes. The test does not
demonstrate exploitability on unpatched builds beyond the dangling reference
being reachable, and it is not a Valgrind/ASan memory report.
