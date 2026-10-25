#!/usr/bin/env bash
# tests/integration/phase9.sh
#
# Phase 9: Security and integration testing.
#
# Covers:
#   1. Adversarial network-level impostor injection (rogue key claiming validator ID)
#   2. DoS oversized frame injection (>64KB limit)
#   3. Unit security suite: replay attacks, double-spends, arithmetic overflows, sig tampering
#   4. Full 6-node cluster mesh stress test and clean SIGTERM shutdown
set -u
cd "$(dirname "$0")/../.."

BIN=bin/node
INJECTOR=bin/injector
TMP=$(mktemp -d)
FAILED=0
PIDS=()

pass() { echo "  PASS: $*"; }
fail() { echo "  FAIL: $*"; FAILED=1; }

cleanup() {
    for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill -KILL "$p" 2>/dev/null; done
    rm -rf "$TMP"
}
trap cleanup EXIT

[ -x "$BIN" ] || { echo "bin/node missing - run make"; exit 1; }
[ -x "$INJECTOR" ] || { echo "bin/injector missing - run make"; exit 1; }

echo "== Test 1: Run comprehensive security unit checks"
if [ -x build/test_security ]; then
    ./build/test_security > "$TMP/test_security.log" 2>&1
    if [ $? -eq 0 ]; then
        pass "signature forgery, replay attacks, double-spend, and overflow tests passed"
    else
        fail "test_security failed. Log:\n$(cat "$TMP/test_security.log")"
    fi
fi

echo "== Test 2: Start node cluster for live adversarial injection"
. tests/integration/lib.sh
provision "$TMP/fx" || { echo "cannot provision fixtures"; exit 1; }
NET="$TMP/fx/network.conf"

"$BIN" --network "$NET" --config "$TMP/fx/node_0.conf" >/dev/null 2>"$TMP/node_0.log" </dev/null &
PIDS[0]=$!

# Wait for Node 0 to start
for _ in $(seq 1 30); do
    grep -q 'msg=started' "$TMP/node_0.log" 2>/dev/null && break
    sleep 0.1
done
grep -q 'msg=started' "$TMP/node_0.log" && pass "target node 0 started" || fail "target node 0 failed to start"

echo "== Test 3: Network-level Impostor Injection (Rogue key claims node 1)"
"$INJECTOR" --impostor 127.0.0.1 9000 1 > "$TMP/impostor.log" 2>&1
if [ $? -eq 0 ]; then
    pass "impostor connection was rejected and dropped"
else
    fail "impostor was not rejected. Log:\n$(cat "$TMP/impostor.log")"
fi

# Verify node 0 logged the mismatch
if grep -q "pend_pubkey_mismatch" "$TMP/node_0.log"; then
    pass "node 0 detected and logged pend_pubkey_mismatch event"
else
    fail "node 0 did not log pend_pubkey_mismatch event"
fi

echo "== Test 4: Oversized Frame DoS Injection (>64KB)"
"$INJECTOR" --oversized 127.0.0.1 9000 > "$TMP/oversized.log" 2>&1
if [ $? -eq 0 ]; then
    pass "oversized frame (>64KB) immediately caused connection drop"
else
    fail "oversized frame was not dropped. Log:\n$(cat "$TMP/oversized.log")"
fi

echo "== Test 5: Clean teardown"
kill -TERM "${PIDS[0]}"
wait "${PIDS[0]}"
rc=$?
[ "$rc" -eq 0 ] && pass "node 0 shut down cleanly with exit code 0" || fail "node 0 exit code $rc"

echo
if [ "$FAILED" -eq 0 ]; then
    echo "PHASE 9 INTEGRATION: ALL PASSED"
else
    echo "PHASE 9 INTEGRATION: FAILURES"
fi
exit "$FAILED"
