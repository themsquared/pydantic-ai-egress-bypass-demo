#!/usr/bin/env bash
# Runs all three scenarios in order. Every step's exit code is checked
# explicitly -- a "VULNERABLE" exit (1) from step 1 is the EXPECTED result,
# demonstrating the bug; "BLOCKED" (0) is expected from steps 2 and 3.
set -u
cd "$(dirname "$0")"

METADATA_PID=""
PROXY_PID=""
cleanup() {
  [ -n "$METADATA_PID" ] && kill "$METADATA_PID" 2>/dev/null
  [ -n "$PROXY_PID" ] && kill "$PROXY_PID" 2>/dev/null
}
trap cleanup EXIT

echo "=== starting metadata_stub.py (127.0.0.1:8169, stands in for cloud metadata) ==="
python3 metadata_stub.py &
METADATA_PID=$!
sleep 0.5

echo
echo "=== scenario 1: app-level check with a DNS-rebind TOCTOU gap (vulnerable_fetch.py) ==="
echo "    expect: VULNERABLE (exit 1) -- the check sees one IP, the connect sees another"
python3 vulnerable_fetch.py
s1=$?
if [ "$s1" -ne 1 ]; then
  echo "FAIL: expected exit 1 (VULNERABLE), got $s1"
  exit 1
fi
echo "    -> got expected exit 1"

echo
echo "=== scenario 2: same bug class, fixed by resolving once and pinning the IP (fixed_fetch.py) ==="
echo "    expect: BLOCKED (exit 0) -- check and connect use the same resolution"
python3 fixed_fetch.py
s2=$?
if [ "$s2" -ne 0 ]; then
  echo "FAIL: expected exit 0 (BLOCKED), got $s2"
  exit 1
fi
echo "    -> got expected exit 0"

echo
echo "=== starting egress_proxy.py (127.0.0.1:8899, network-layer enforcement) ==="
python3 egress_proxy.py &
PROXY_PID=$!
sleep 0.5

echo
echo "=== scenario 3: client with NO allowlist check at all, routed through the proxy ==="
echo "    expect: BLOCKED (exit 0) -- the proxy enforces policy regardless of client logic"
python3 fetch_through_proxy.py
s3=$?
if [ "$s3" -ne 0 ]; then
  echo "FAIL: expected exit 0 (BLOCKED), got $s3"
  exit 1
fi
echo "    -> got expected exit 0"

echo
echo "=== all three scenarios matched expected behavior ==="
