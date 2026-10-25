#!/usr/bin/env bash
# Phase 1 integration test: six real processes + bad-config rejection.
# Uses ports 9000-9005 on 127.0.0.1 - they must be free.
set -u
cd "$(dirname "$0")/../.."

BIN=bin/node
TMP=$(mktemp -d)
. tests/integration/lib.sh
provision "$TMP/fx" || { echo "cannot provision fixtures"; exit 1; }
NET="$TMP/fx/network.conf"
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

echo "== Test 1: six nodes start with the roles from network.conf"
for i in 0 1 2 3 4 5; do
    "$BIN" --network "$NET" --config "$TMP/fx/node_$i.conf" 2>"$TMP/node_$i.log" &
    PIDS[$i]=$!
done

# Wait up to 5s for every node to log 'started'.
for _ in $(seq 1 50); do
    n=$(grep -l 'msg=started' "$TMP"/node_*.log 2>/dev/null | wc -l)
    [ "$n" -eq 6 ] && break
    sleep 0.1
done
[ "$n" -eq 6 ] && pass "all 6 nodes logged msg=started" || fail "only $n/6 nodes started"

v=$(cat "$TMP"/node_*.log | grep 'msg=started' | grep -c 'role=validator')
m=$(cat "$TMP"/node_*.log | grep 'msg=started' | grep -c 'role=normal')
[ "$v" -eq 2 ] && pass "exactly 2 validators" || fail "validators=$v (want 2)"
[ "$m" -eq 4 ] && pass "exactly 4 normal nodes" || fail "normal=$m (want 4)"

while read -r _ id role _ port _; do
    if grep -q "node=$id msg=started role=$role .*port=$port" "$TMP/node_$id.log"; then
        pass "node $id role=$role port=$port matches config"
    else
        fail "node $id does not match config (role=$role port=$port)"
    fi
done < <(grep '^node ' "$NET" | sed 's/#.*//')

echo "== Test 2: SIGTERM shuts every node down cleanly"
for p in "${PIDS[@]}"; do kill -TERM "$p"; done
for i in 0 1 2 3 4 5; do
    wait "${PIDS[$i]}"; rc=$?
    [ "$rc" -eq 0 ] && grep -q 'msg=shutdown' "$TMP/node_$i.log" \
        && pass "node $i exited 0 and logged shutdown" \
        || fail "node $i rc=$rc / no shutdown log"
done
for p in "${PIDS[@]}"; do
    kill -0 "$p" 2>/dev/null && fail "process $p still alive" || true
done
pass "no stray node processes remain"
PIDS=()

echo "== Test 3: bad configuration is rejected"
expect_reject() {   # name net-file node-file
    local out rc
    out=$(timeout 5 "$BIN" --network "$2" --config "$3" 2>&1); rc=$?
    if [ "$rc" -ne 0 ] && [ "$rc" -ne 124 ] && grep -q 'msg=config_error' <<<"$out"; then
        pass "$1 (exit $rc)"
    else
        fail "$1 (exit $rc): $out"
    fi
}

sed 's/node 3 normal/node 3 observer/' "$NET" >"$TMP/bad_role.conf"
expect_reject "unknown role"          "$TMP/bad_role.conf" $TMP/fx/node_3.conf

{ cat "$NET"; echo "node 2 normal 127.0.0.1 9099"; } >"$TMP/dup_id.conf"
expect_reject "duplicate node id"     "$TMP/dup_id.conf"   $TMP/fx/node_2.conf

sed 's/ 9005 / 9004 /' "$NET" >"$TMP/dup_port.conf"
expect_reject "duplicate port"        "$TMP/dup_port.conf" $TMP/fx/node_2.conf

sed 's/node_id  = 2/node_id  = 7/' $TMP/fx/node_2.conf >"$TMP/id_not_in_net.conf"
expect_reject "node id not in network" "$NET"              "$TMP/id_not_in_net.conf"

grep -v key_path $TMP/fx/node_2.conf >"$TMP/no_key.conf"
expect_reject "missing key_path"      "$NET"               "$TMP/no_key.conf"

sed 's/node 2 normal/node 2 validator/' "$NET" >"$TMP/bad_topo.conf"
expect_reject "wrong topology (3 validators)" "$TMP/bad_topo.conf" $TMP/fx/node_2.conf

expect_reject "missing network file"  "$TMP/nope.conf"     $TMP/fx/node_2.conf

echo
if [ "$FAILED" -eq 0 ]; then echo "PHASE 1 INTEGRATION: ALL PASSED"; else echo "PHASE 1 INTEGRATION: FAILURES"; fi
exit "$FAILED"
