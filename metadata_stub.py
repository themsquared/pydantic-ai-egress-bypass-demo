#!/usr/bin/env python3
"""Stands in for a real cloud-metadata endpoint (e.g. Tencent Cloud's
169.254.0.23, the gap in GHSA-5fj9-5pjw-vpwc's blocklist). Binds plain
127.0.0.1 so the demo needs no special privileges or OS-specific loopback
aliasing -- the scripts in this repo treat 127.0.0.1 as "forbidden" and an
RFC 5737 documentation address as "safe" instead of using two different
loopback IPs.
"""
import http.server

HOST = "127.0.0.1"
PORT = 8169
FAKE_SECRET = "FAKE-ROLE-CREDENTIAL-STAND-IN-FOR-CLOUD-METADATA-DO-NOT-USE"


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = FAKE_SECRET.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass


class MetadataServer(http.server.HTTPServer):
    allow_reuse_address = True  # avoid TIME_WAIT bind failures on quick restarts


if __name__ == "__main__":
    server = MetadataServer((HOST, PORT), Handler)
    print(f"metadata_stub listening on {HOST}:{PORT}", flush=True)
    server.serve_forever()
