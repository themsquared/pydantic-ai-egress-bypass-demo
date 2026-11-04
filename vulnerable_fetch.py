#!/usr/bin/env python3
"""The buggy pattern behind GHSA-5ppx-9jq6-6pmw: check the hostname against
an allowlist by resolving it, THEN separately connect to the hostname (which
resolves it again). Two different DNS lookups, two chances for the answer
to differ.

This mirrors the advisory's shape, not its exact code -- pydantic-ai's
allowed_domains check and PlaywrightBrowser's allowlist worked this way
for the resolve-vs-reject ordering; the TOCTOU (time-of-check vs
time-of-use) gap is the same family of bug either way.
"""
import socket
import sys

from rebind_resolver import FORBIDDEN_IP, TARGET_HOST, RebindingDNS

BLOCKLIST_IPS = {FORBIDDEN_IP}


def is_hostname_allowed(hostname: str, port: int) -> bool:
    """Resolve once, check the resolved IP. This is call #1."""
    ip = socket.getaddrinfo(hostname, port)[0][4][0]
    print(f"  [check]   resolved {hostname} -> {ip} for the allowlist check")
    return ip not in BLOCKLIST_IPS


def fetch(hostname: str, port: int, path: str) -> str:
    if not is_hostname_allowed(hostname, port):
        raise PermissionError(f"{hostname} resolved to a blocked IP")
    # socket.create_connection() resolves the hostname AGAIN internally.
    # This is call #2 -- and in our rebind scenario it gets a different answer.
    sock = socket.create_connection((hostname, port), timeout=3)
    print(f"  [connect] connected to {hostname}:{port} (second, independent resolution)")
    try:
        sock.sendall(f"GET {path} HTTP/1.0\r\nHost: {hostname}\r\n\r\n".encode())
        data = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    finally:
        sock.close()
    return data.decode(errors="replace").split("\r\n\r\n", 1)[-1]


if __name__ == "__main__":
    with RebindingDNS():
        body = fetch(TARGET_HOST, 8169, "/")
    print(f"  [result]  response body: {body!r}")
    if "FAKE-ROLE-CREDENTIAL" in body:
        print("VULNERABLE: fetched the forbidden endpoint despite the allowlist check")
        sys.exit(1)
    print("BLOCKED: forbidden endpoint was not reached")
    sys.exit(0)
