#!/usr/bin/env python3
"""A minimal forward proxy that enforces the egress blocklist itself,
using the same resolve-once-then-connect-to-the-pinned-IP pattern as
fixed_fetch.py. The point: this check does not live in the agent's code
at all, so it doesn't matter whether the agent framework's own allowlist
has a TOCTOU bug -- every outbound connection goes through here, and this
is the only place the policy is enforced.

Speaks plain HTTP with an absolute-URI request line, the way an app
configured to use an HTTP proxy would ("GET http://host:port/path HTTP/1.0").
No CONNECT/TLS tunneling -- out of scope for this demo.
"""
import socket
import socketserver
import sys
from urllib.parse import urlsplit

from rebind_resolver import FORBIDDEN_IP, StaticForbiddenDNS

HOST = "127.0.0.1"
PORT = 8899
BLOCKLIST_IPS = {FORBIDDEN_IP}


class ProxyHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request.recv(65536)
        if not data:
            return
        try:
            request_line = data.split(b"\r\n", 1)[0].decode()
            method, target, _ = request_line.split(" ", 2)
            parts = urlsplit(target)
            hostname, port = parts.hostname, parts.port or 80
        except Exception:
            self.request.sendall(b"HTTP/1.0 400 Bad Request\r\n\r\n")
            return

        try:
            ip = socket.getaddrinfo(hostname, port)[0][4][0]  # resolve ONCE, here
        except socket.gaierror:
            self.request.sendall(b"HTTP/1.0 502 Bad Gateway\r\n\r\n")
            return

        print(f"  [proxy]   {method} {target} -> resolved {hostname} -> {ip}", flush=True)
        if ip in BLOCKLIST_IPS:
            print(f"  [proxy]   BLOCKED: {ip} is on the egress blocklist", flush=True)
            self.request.sendall(
                b"HTTP/1.0 403 Forbidden\r\n\r\nblocked by egress_proxy policy"
            )
            return

        upstream = socket.create_connection((ip, port), timeout=3)  # pinned IP
        try:
            upstream.sendall(data)
            while True:
                chunk = upstream.recv(4096)
                if not chunk:
                    break
                self.request.sendall(chunk)
        finally:
            upstream.close()


class ProxyServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True  # avoid TIME_WAIT bind failures on quick restarts
    daemon_threads = True


if __name__ == "__main__":
    with StaticForbiddenDNS():
        server = ProxyServer((HOST, PORT), ProxyHandler)
        print(f"egress_proxy listening on {HOST}:{PORT}", flush=True)
        server.serve_forever()
