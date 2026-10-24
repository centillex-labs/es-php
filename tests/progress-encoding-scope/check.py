#!/usr/bin/env python3
"""Assert the upload-progress encoding boundary.

Usage: check.py <base-url> <container> <patched|baseline>

Sends one multipart request carrying hostile bytes in every attacker-reachable
field, then asserts:
  * what patch 003 encodes (session key, field_name, name)
  * what it must leave alone ($_FILES, and '>' inside the name)

The baseline mode asserts the pre-patch values, so the test can actually fail --
a test that passes on both builds proves nothing.
"""
import json
import socket
import subprocess
import sys

BOUNDARY = "SCOPEBOUNDARY"

# '<' and '|' are the security-relevant bytes; '>' is the control character
# that must survive untouched.
HOSTILE_NAME = "a<b>c|d.txt"
HOSTILE_FIELD = "f<2"
PROGRESS_NAME = "p<1"

EXPECT = {
    "patched": {
        "files_name": HOSTILE_NAME,                       # $_FILES untouched
        "session_key": "upload_progress_p%3C1",
        "progress_files": [
            {"field_name": "f", "name": "a%3Cb>c%7Cd.txt"},   # '>' preserved
            {"field_name": "f%3C2", "name": "safe.txt"},
        ],
        # '<' must be gone from the file, so the session file cannot open a PHP
        # tag. '|' is NOT forbidden: the php serializer's own key/value
        # delimiter is a '|' ("upload_progress_...|a:5:{...}"), so the file
        # always contains one. That the attacker's '|' is neutralised is
        # asserted by the progress_files equality check instead.
        "forbid_in_session_file": ["<", HOSTILE_NAME],
        "require_in_session_file": [],
    },
    "baseline": {
        "files_name": HOSTILE_NAME,
        "session_key": "upload_progress_p<1",
        "progress_files": [
            {"field_name": "f", "name": HOSTILE_NAME},
            {"field_name": HOSTILE_FIELD, "name": "safe.txt"},
        ],
        # The baseline must still carry the raw bytes, otherwise this test
        # could not fail and would prove nothing.
        "forbid_in_session_file": [],
        "require_in_session_file": [HOSTILE_NAME],
    },
}


def multipart() -> bytes:
    return (
        f"--{BOUNDARY}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        f"{PROGRESS_NAME}\r\n"
        f"--{BOUNDARY}\r\n"
        f'Content-Disposition: form-data; name="f"; filename="{HOSTILE_NAME}"\r\n'
        f"Content-Type: text/plain\r\n\r\nhello\r\n"
        f"--{BOUNDARY}\r\n"
        f'Content-Disposition: form-data; name="{HOSTILE_FIELD}"; filename="safe.txt"\r\n'
        f"Content-Type: text/plain\r\n\r\nworld\r\n"
        f"--{BOUNDARY}--\r\n"
    ).encode("latin-1")


def post(host: str, port: int, path: str, sid: str) -> str:
    body = multipart()
    request = (
        f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
        f"Content-Type: multipart/form-data; boundary={BOUNDARY}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Cookie: PHPSESSID={sid}\r\nConnection: close\r\n\r\n"
    ).encode() + body
    sock = socket.create_connection((host, port), timeout=20)
    sock.sendall(request)
    sock.settimeout(20)
    data = b""
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            break
        data += chunk
    sock.close()
    return data.decode("latin-1", "replace")


def session_file(container: str, sid: str) -> str:
    result = subprocess.run(
        ["docker", "exec", container, "sh", "-c", f"cat /scope/sess/sess_{sid}"],
        capture_output=True, text=True,
    )
    return result.stdout


def main() -> int:
    base, container, mode = sys.argv[1], sys.argv[2], sys.argv[3]
    host, _, port_s = base.replace("http://", "").partition(":")
    expected = EXPECT[mode]
    # Distinct SID per mode: sharing one would let the patched run's session
    # file leak into the baseline run and mask a regression.
    sid = f"scopesid{mode}0000000000000"

    response = post(host, int(port_s or 80), "/index.php", sid)
    body = response.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in response else response
    try:
        got = json.loads(body)
    except ValueError:
        print(f"FAIL: no JSON in response:\n{body[:400]}", file=sys.stderr)
        return 1

    failures = []
    for field in ("files_name", "session_key"):
        if got.get(field) != expected[field]:
            failures.append(f"{field}: got {got.get(field)!r}, want {expected[field]!r}")
    if got.get("progress_files") != expected["progress_files"]:
        failures.append(
            f"progress_files: got {got.get('progress_files')!r}, "
            f"want {expected['progress_files']!r}"
        )

    on_disk = session_file(container, sid)
    if not on_disk:
        failures.append(f"no session file written for {sid}")
    for bad in expected["forbid_in_session_file"]:
        if bad in on_disk:
            failures.append(f"session file still contains raw {bad!r}")
    for want in expected["require_in_session_file"]:
        if want not in on_disk:
            failures.append(f"baseline session file is missing raw {want!r} -- did the patch leak in?")

    if failures:
        print(f"FAIL ({mode})")
        for failure in failures:
            print(f"  - {failure}")
        return 1

    print(f"PASS ({mode}): $_FILES raw; progress record encoded as expected")
    if expected["forbid_in_session_file"]:
        print("  session file carries no raw '<' and no raw hostile filename")
    else:
        print("  baseline stores the raw bytes, so this test can fail")
    return 0


if __name__ == "__main__":
    sys.exit(main())
