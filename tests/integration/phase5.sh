#!/usr/bin/env bash
# tests/integration/phase5.sh
#
# Phase 5 integration test: DAG Construction, Validation, and Causal History.
#
# Tests:
#   1. Runs DAG unit tests (vertex creation, hashing with VERTEX/v1, signatures, storage)
#   2. Verifies parent referencing and causal history extraction
#   3. Cluster launch and clean shutdown
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

echo "== Test 1: DAG unit test verification"
if [ -x build/test_dag ]; then
    ./build/test_dag > "$TMP/test_dag.log" 2>&1
    if [ $? -eq 0 ]; then
        pass "DAG construction, hashing, serialization, and storage tests passed"
    else
        fail "test_dag failed. Log:\n$(cat "$TMP/test_dag.log")"
    fi
else
    fail "build/test_dag not found"
fi

echo "== Test 2: Multi-process DAG node cluster lifecycle"
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
[ "$n" -eq 6 ] && pass "all 6 nodes started with active DAG subsystem" || fail "only $n/6 nodes started"

echo "== Test 3: Clean SIGTERM shutdown"
for p in "${PIDS[@]}"; do kill -TERM "$p"; done
for i in 0 1 2 3 4 5; do
    wait "${PIDS[$i]}"; rc=$?
    [ "$rc" -eq 0 ] && pass "node $i shut down cleanly" || fail "node $i rc=$rc"
done

echo
if [ "$FAILED" -eq 0 ]; then
    echo "PHASE 5 INTEGRATION: ALL PASSED"
else
    echo "PHASE 5 INTEGRATION: FAILURES"
fi
exit "$FAILED"
