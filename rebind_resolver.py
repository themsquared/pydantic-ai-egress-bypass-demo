"""Mocks for a hostname whose resolution changes depending on who's asking
and when -- the mechanism behind GHSA-5ppx-9jq6-6pmw (allowed_domains /
PlaywrightBrowser egress allowlists resolved a hostname via DNS, separately,
more than once, and an attacker who controls that DNS record can answer
differently each time). A real attack does this with a short TTL against a
DNS server the attacker controls; this demo does it in-process so the whole
thing is deterministic and needs no network access or special privileges.

SAFE_IP is an address from RFC 5737's documentation range (203.0.113.0/24):
guaranteed never to be live anywhere, used only so the "check" step has
something that isn't on the blocklist to compare against -- it never
actually gets connected to.

FORBIDDEN_IP is 127.0.0.1, where metadata_stub.py really listens, standing
in for a real cloud-metadata address (e.g. Tencent Cloud's 169.254.0.23,
the gap in GHSA-5fj9-5pjw-vpwc's blocklist).
"""
import socket

TARGET_HOST = "api.example-safe.test"
SAFE_IP = "203.0.113.10"
FORBIDDEN_IP = "127.0.0.1"

_real_getaddrinfo = socket.getaddrinfo


class RebindingDNS:
    """First lookup of TARGET_HOST in this process returns SAFE_IP. Every
    lookup after that returns FORBIDDEN_IP -- simulating a DNS record that
    rebinds between the moment code checks it and the moment code uses it.
    """

    def __init__(self):
        self.call_count = 0
        self._patched = False

    def _fake_getaddrinfo(self, host, port, *args, **kwargs):
        if host != TARGET_HOST:
            return _real_getaddrinfo(host, port, *args, **kwargs)
        self.call_count += 1
        ip = SAFE_IP if self.call_count == 1 else FORBIDDEN_IP
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port))]

    def __enter__(self):
        socket.getaddrinfo = self._fake_getaddrinfo
        self._patched = True
        return self

    def __exit__(self, *exc):
        if self._patched:
            socket.getaddrinfo = _real_getaddrinfo
        return False


class StaticForbiddenDNS:
    """DNS has already finished rebinding: every lookup of TARGET_HOST, in
    any process, now returns the forbidden IP. Used for the cross-process
    proxy demo, where the point isn't the check-vs-connect timing gap, it's
    that enforcement happens at the network boundary instead of in app code
    at all.
    """

    def __init__(self):
        self._patched = False

    def _fake_getaddrinfo(self, host, port, *args, **kwargs):
        if host != TARGET_HOST:
            return _real_getaddrinfo(host, port, *args, **kwargs)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (FORBIDDEN_IP, port))]

    def __enter__(self):
        socket.getaddrinfo = self._fake_getaddrinfo
        self._patched = True
        return self

    def __exit__(self, *exc):
        if self._patched:
            socket.getaddrinfo = _real_getaddrinfo
        return False
