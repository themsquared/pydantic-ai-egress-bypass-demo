#!/usr/bin/env python3
"""A client with NO allowlist check at all -- standing in for "whatever
bug-of-the-week hits the app's own egress logic next" (a TOCTOU gap like
GHSA-5ppx-9jq6-6pmw, a missing IP in a blocklist like GHSA-5fj9-5pjw-vpwc,
or a check that was simply never written). It asks egress_proxy.py to
fetch the target on its behalf. The point: it doesn't matter that this
client skips the check entirely, because it isn't the one enforcing policy.
"""
import socket
import sys

from rebind_resolver import TARGET_HOST

PROXY_HOST, PROXY_PORT = "127.0.0.1", 8899


def fetch_via_proxy(hostname: str, port: int, path: str) -> tuple[int, str]:
    sock = socket.create_connection((PROXY_HOST, PROXY_PORT), timeout=3)
    try:
        request = f"GET http://{hostname}:{port}{path} HTTP/1.0\r\nHost: {hostname}\r\n\r\n"
        sock.sendall(request.encode())
        data = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    finally:
        sock.close()
    text = data.decode(errors="replace")
    status_line, _, body = text.partition("\r\n\r\n")
    status_code = int(status_line.split(" ", 2)[1])
    return status_code, body


if __name__ == "__main__":
    status, body = fetch_via_proxy(TARGET_HOST, 8169, "/")
    print(f"  [client]  no allowlist check performed; proxy returned HTTP {status}")
    print(f"  [result]  body: {body!r}")
    if status == 403:
        print("BLOCKED: the proxy enforced the policy even though the client never checked")
        sys.exit(0)
    if "FAKE-ROLE-CREDENTIAL" in body:
        print("VULNERABLE: forbidden endpoint reached through the proxy")
        sys.exit(1)
    print(f"UNEXPECTED: HTTP {status}")
    sys.exit(2)
