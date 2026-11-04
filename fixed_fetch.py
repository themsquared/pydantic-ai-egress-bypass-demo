#!/usr/bin/env python3
"""The fix: resolve the hostname exactly once, check that single result
against the blocklist, and connect to the resolved IP directly (pinned),
never giving the hostname a second chance to resolve to something else.
"""
import socket
import sys

from rebind_resolver import FORBIDDEN_IP, TARGET_HOST, StaticForbiddenDNS

BLOCKLIST_IPS = {FORBIDDEN_IP}


def fetch(hostname: str, port: int, path: str) -> str:
    ip = socket.getaddrinfo(hostname, port)[0][4][0]  # resolve ONCE
    print(f"  [check]   resolved {hostname} -> {ip} for the allowlist check")
    if ip in BLOCKLIST_IPS:
        raise PermissionError(f"{hostname} resolved to a blocked IP ({ip})")
    # Connect to the PINNED ip -- no second resolution, no second chance
    # for the answer to change.
    sock = socket.create_connection((ip, port), timeout=3)
    print(f"  [connect] connected to pinned IP {ip}:{port} (same resolution as the check)")
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
    with StaticForbiddenDNS():
        try:
            body = fetch(TARGET_HOST, 8169, "/")
        except PermissionError as e:
            print(f"BLOCKED: {e}")
            sys.exit(0)
    print(f"  [result]  response body: {body!r}")
    print("UNEXPECTED: fixed code reached the forbidden endpoint")
    sys.exit(1)
