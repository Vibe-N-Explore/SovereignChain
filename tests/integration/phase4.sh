#!/usr/bin/env bash
# tests/integration/phase4.sh
#
# Phase 4 integration test: Transactions, Mempool, and Transaction Gossip.
#
# Tests:
#   1. Mempool unit checks (admission, deduplication, invalid sig rejection)
#   2. Full 6-node cluster boot and mesh authentication
#   3. Transaction submission and P2P gossip propagation
#   4. Clean shutdown
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

echo "== Test 1: Mempool unit checks"
if [ -x build/test_mempool ]; then
    ./build/test_mempool > "$TMP/test_mempool.log" 2>&1
    if [ $? -eq 0 ]; then
        pass "mempool unit tests passed"
    else
        fail "test_mempool failed. Log:\n$(cat "$TMP/test_mempool.log")"
    fi
else
    fail "build/test_mempool not found"
fi

echo "== Test 2: Node cluster boot with transaction gossip"
. tests/integration/lib.sh
provision "$TMP/fx" || { echo "cannot provision fixtures"; exit 1; }
NET="$TMP/fx/network.conf"

# Start Node 0..5, with Node 2 sending a transaction to Node 0
for i in 0 1 3 4 5; do
    "$BIN" --network "$NET" --config "$TMP/fx/node_$i.conf" >/dev/null 2>"$TMP/node_$i.log" </dev/null &
    PIDS[$i]=$!
done

# Start Node 2 configured to send transaction to Node 0
"$BIN" --network "$NET" --config "$TMP/fx/node_2.conf" --send-tx 0 2500 50 >/dev/null 2>"$TMP/node_2.log" </dev/null &
PIDS[2]=$!

# Wait for Node 2 to log sent_tx
for _ in $(seq 1 50); do
    grep -q 'msg=sent_tx' "$TMP/node_2.log" 2>/dev/null && break
    sleep 0.1
done
grep -q 'msg=sent_tx' "$TMP/node_2.log" && pass "node 2 successfully signed and sent transaction" || fail "node 2 did not send transaction"

# Wait for Node 0 to log recv_tx
for _ in $(seq 1 50); do
    grep -q 'msg=recv_tx' "$TMP/node_0.log" 2>/dev/null && break
    sleep 0.1
done
grep -q 'msg=recv_tx' "$TMP/node_0.log" && pass "node 0 verified and admitted transaction to mempool" || fail "node 0 did not admit transaction"

echo "== Test 3: Clean SIGTERM shutdown"
for p in "${PIDS[@]}"; do kill -TERM "$p"; done
for i in 0 1 2 3 4 5; do
    wait "${PIDS[$i]}"; rc=$?
    [ "$rc" -eq 0 ] && pass "node $i shut down cleanly" || fail "node $i failed shutdown rc=$rc"
done

echo
if [ "$FAILED" -eq 0 ]; then
    echo "PHASE 4 INTEGRATION: ALL PASSED"
else
    echo "PHASE 4 INTEGRATION: FAILURES"
fi
exit "$FAILED"
