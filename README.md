# pydantic-ai egress bypass demo

Reproduces the shape of two security advisories pydantic AI disclosed
together on 2026-11-04, in `pydantic-ai` v2.66.0 / v1.107.10 /
`pydantic-ai-harness` 0.66.0:

- **[GHSA-5ppx-9jq6-6pmw](https://github.com/pydantic/pydantic-ai/security/advisories/GHSA-5ppx-9jq6-6pmw)** (low): `allowed_domains` on the local web-fetch tool, and `PlaywrightBrowser` egress allowlists, looked a hostname up in DNS, decided whether it was allowed, and only then connected — resolving the hostname again. A hostname an attacker controls can answer differently each time.
- **[GHSA-5fj9-5pjw-vpwc](https://github.com/pydantic/pydantic-ai/security/advisories/GHSA-5fj9-5pjw-vpwc)** (medium): the cloud-metadata blocklist that URL downloads check was missing Tencent Cloud's instance-metadata address, `169.254.0.23`. A blocklist is only as good as the addresses someone remembered to put in it.

Both bugs put the egress decision *inside the agent's own process*. This
repo builds a small, runnable version of each bug, then shows a third
option: move the check to a proxy in front of the agent, so the policy
holds even when the agent's own logic has a bug like these — or simply
never checks at all.

## The value proposition this maps to

This is the argument for `agentgateway` as an **egress policy enforcement
point**: a network chokepoint that resolves a destination once and pins
the connection to that resolution, independent of whatever the agent
framework's own allowlist code does or doesn't do correctly this release.
An app-level blocklist has to enumerate every cloud provider's metadata
address and get the check-then-connect ordering right, forever, in every
language binding. A gateway only has to do it once, in one place, for
every agent behind it.

## What's in here

| File | Role |
|---|---|
| `metadata_stub.py` | A fake endpoint standing in for a real cloud-metadata service, bound to `127.0.0.1:8169` (serves a fake credential string, nothing real) |
| `rebind_resolver.py` | Mocks a hostname whose DNS answer changes between lookups (`RebindingDNS`) or has already settled on the forbidden answer (`StaticForbiddenDNS`) — no real network or DNS server needed |
| `vulnerable_fetch.py` | The buggy pattern: resolve once to check an allowlist, then connect (which resolves *again*) |
| `fixed_fetch.py` | The fix: resolve exactly once, check that result, connect to the pinned IP |
| `egress_proxy.py` | A ~70-line forward proxy that enforces the same resolve-once-pin-the-IP policy, in front of any client |
| `fetch_through_proxy.py` | A client that performs **no allowlist check at all**, routed through the proxy |
| `demo.sh` | Runs all three scenarios and checks each exit code against what's expected |

This is a demo-sized model of the bug class, not a reproduction of
pydantic-ai's actual source. It uses an RFC 5737 documentation address
(`203.0.113.10`) as the "safe" answer and `127.0.0.1` as the "forbidden"
one (standing in for a real cloud-metadata IP), so the whole thing runs
locally with no sudo, no second loopback alias, and no live network
access.

## Quickstart

Requires Python 3.9+, standard library only (no pip installs).

```bash
git clone https://github.com/themsquared/pydantic-ai-egress-bypass-demo.git
cd pydantic-ai-egress-bypass-demo
bash demo.sh
```

Expected output, in order:

1. **`vulnerable_fetch.py`** exits 1, printing `VULNERABLE: fetched the
   forbidden endpoint despite the allowlist check` — the check resolves
   the safe address, the connect resolves the forbidden one.
2. **`fixed_fetch.py`** exits 0, printing `BLOCKED: ... resolved to a
   blocked IP` — one resolution, used for both the check and the connect.
3. **`fetch_through_proxy.py`**, talking to `egress_proxy.py`, exits 0,
   printing `BLOCKED: the proxy enforced the policy even though the
   client never checked` — the client performs no check of its own at
   all, and the outcome doesn't change.

To see each piece run on its own:

```bash
python3 metadata_stub.py &        # fake metadata endpoint on 127.0.0.1:8169
python3 vulnerable_fetch.py       # exits 1 (VULNERABLE)
python3 fixed_fetch.py            # exits 0 (BLOCKED)
python3 egress_proxy.py &         # proxy on 127.0.0.1:8899
python3 fetch_through_proxy.py    # exits 0 (BLOCKED), no client-side check at all
```

Every command above was run against this exact repo before publishing;
`demo.sh` was executed three times back to back with no stale-process
failures.

## Architecture notes

- `socket.getaddrinfo` is monkeypatched for the single hostname
  `api.example-safe.test`; every other hostname resolves normally.
  `RebindingDNS` returns the "safe" address on the first lookup in a
  process and the "forbidden" one on every lookup after that, modeling a
  DNS record with a short TTL that an attacker rebinds between the
  moment your code checks it and the moment your code uses it.
  `StaticForbiddenDNS` always returns the forbidden address, modeling a
  record that has already finished rebinding by the time anything looks
  it up — used for the proxy scenario, where the point isn't the timing
  gap, it's that the client's logic (or lack of it) doesn't matter.
- `egress_proxy.py` speaks plain HTTP with an absolute-URI request line
  (`GET http://host:port/path HTTP/1.0`), the way a client configured to
  use an HTTP proxy would send it. It does not implement `CONNECT`/TLS
  tunneling — out of scope for this demo.
- None of this depends on `pydantic-ai` itself; it models the bug class
  pydantic-ai disclosed, built from scratch in the standard library, so
  it has no dependency on which version of the library is installed.

## What this demo does NOT verify

- It does not run against the actual `pydantic-ai` package or reproduce
  its exact code path — the real advisories are linked above for that.
- It does not model a real DNS rebind over the network (short TTL,
  external resolver); the "DNS" here is an in-process mock.
- `egress_proxy.py` is a teaching toy, not a production egress gateway —
  no TLS inspection, no SNI-based policy, no connection pooling. For the
  real thing, see `agentgateway`.

## License

Apache-2.0. See [LICENSE](LICENSE).

Topics: `agentgateway`, `mcp`, `agent-security`, `egress-control`, `ssrf`
