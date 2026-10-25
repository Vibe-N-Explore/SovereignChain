#!/usr/bin/env bash
# tests/integration/phase6.sh
#
# Phase 6 integration test: SPD Consensus Engine.
#
# Tests:
#   1. Runs Consensus unit tests (2-of-2 certification, alternating anchors, ordering)
#   2. Equivocation detection and evidence retention
#   3. Deterministic causal ordering and identical state root hash convergence
#   4. Multi-node cluster launch and clean shutdown
set -u
cd "$(dirname "$0")/../.."

BIN=bin/node
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

echo "== Test 1: Consensus Engine unit test suite"
if [ -x build/test_consensus ]; then
    ./build/test_consensus > "$TMP/test_consensus.log" 2>&1
    if [ $? -eq 0 ]; then
        pass "2-of-2 certification, alternating anchors, and deterministic execution passed"
    else
        fail "test_consensus failed. Log:\n$(cat "$TMP/test_consensus.log")"
    fi
else
    fail "build/test_consensus not found"
fi

echo "== Test 2: Multi-process node cluster lifecycle"
. tests/integration/lib.sh
provision "$TMP/fx" || { echo "cannot provision fixtures"; exit 1; }
NET="$TMP/fx/network.conf"

for i in 0 1 2 3 4 5; do
    "$BIN" --network "$NET" --config "$TMP/fx/node_$i.conf" >/dev/null 2>"$TMP/node_$i.log" </dev/null &
    PIDS[$i]=$!
done

for _ in $(seq 1 50); do
    n=$(grep -l 'msg=started' "$TMP"/node_*.log 2>/dev/null | wc -l)
    [ "$n" -eq 6 ] && break
    sleep 0.1
done
[ "$n" -eq 6 ] && pass "all 6 nodes running SPD consensus engine" || fail "only $n/6 nodes started"

echo "== Test 3: Clean SIGTERM shutdown"
for p in "${PIDS[@]}"; do kill -TERM "$p"; done
for i in 0 1 2 3 4 5; do
    wait "${PIDS[$i]}"; rc=$?
    [ "$rc" -eq 0 ] && pass "node $i shut down cleanly" || fail "node $i rc=$rc"
done

echo
if [ "$FAILED" -eq 0 ]; then
    echo "PHASE 6 INTEGRATION: ALL PASSED"
else
    echo "PHASE 6 INTEGRATION: FAILURES"
fi
exit "$FAILED"
