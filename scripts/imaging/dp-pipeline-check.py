#!/usr/bin/env python3
"""Send an allowed request and a denied one down one connection; expect one answer.

The docker CLI keeps connections alive and sends its next request down the same
socket. A proxy that inspected the first request and then relayed the rest raw
would pass everything after it — and everything after it is chosen by whoever is
talking to the proxy. `GET /version`, then `POST /containers/other/exec` on the
same socket, and the allowlist never sees the second one.

Both requests are written in a single send, so the second is already sitting in
the proxy's buffer when it decides about the first. That is exactly the shape a
check-once-then-tunnel proxy passes, and the shape this one has to refuse.

Used by scripts/test-docker-proxy.sh; kept as its own file because a heredoc
inside a shell heredoc inside a test is not something anyone should have to read.
"""

import socket
import sys


def main(path: str) -> int:
    body = b'{"Cmd":["id"],"AttachStdout":true}'
    request = (
        b"GET /v1.45/version HTTP/1.1\r\nHost: d\r\n\r\n"
        b"POST /containers/dp-test-victim/exec HTTP/1.1\r\nHost: d\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    )
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(10)
    try:
        sock.connect(path)
        sock.sendall(request)
        data = b""
        while True:
            try:
                chunk = sock.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
    finally:
        sock.close()

    # Either the connection was closed after the first response (what this proxy
    # does, by forcing Connection: close) or the second was refused. Both are
    # fine. A created exec — which answers 201 with an {"Id": ...} — is not.
    statuses = [part[:3].decode("latin-1", "replace")
                for part in data.split(b"HTTP/1.1 ")[1:]]
    print(f"  responses on that connection: {statuses or ['(none)']}")
    smuggled = b'"Id"' in data and (b"HTTP/1.1 201" in data or b"HTTP/1.1 200" in data
                                    and b"/exec" not in data[:40])
    if smuggled:
        print("  the exec was created — the second request was never checked")
        return 1
    if len(statuses) > 1 and statuses[1].startswith("2"):
        print("  the second request got a 2xx, so it reached the daemon")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
