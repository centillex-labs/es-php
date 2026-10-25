# CVE-2020-7066 (bug #79329) regression

`get_headers()` accepted a URL containing a NUL byte and silently truncated the
request there, so `http://host/safe\0/evil` was fetched as `/safe`.

## How it is measured

The child process opens an ephemeral listening socket, then calls
`get_headers()` on `http://<that socket>/aaaa\0/secret`. It afterwards reports:

- whether a connection arrived,
- the exact request line,
- the return type of `get_headers()`,
- the warning text,
- a computed marker (`137 * 149`).

| Build | Connected | Request line | Return |
| --- | --- | --- | --- |
| unpatched | yes | `GET /aaaa HTTP/1.0` | `false` (request fails) |
| patched | no | — | `NULL` + "expects parameter 1 to be a valid path" |

The truncation is proven by the request line, not by the return value: an
unpatched build connects and drops the trailing path.

## Port

Upstream changed `Z_PARAM_STRING` to `Z_PARAM_PATH`. PHP 5 has no
`Z_PARAM_PATH`; the equivalent is the `p` specifier, which shares the `s` code
path in `Zend/zend_API.c` and adds only `CHECK_ZVAL_NULL_PATH`. Behavior for
valid URLs, including relative paths, is unchanged.

## Run

```sh
tests/get-headers-nul/run.sh
tests/get-headers-nul/run.sh 5.6
```

Reports: `work/reports/php-<branch>-get-headers-{fixed,baseline}.json`.

## Limits

The test proves the argument is rejected and no connection is made. It does not
exercise the network layer that made truncation interesting in the first place
(e.g. filtered hosts or allow-list based SSRF defenses); `--network none` is used
so nothing leaves the container.
