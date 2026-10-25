#!/usr/bin/env bash
# tests/integration/phase3.sh
#
# Phase 3 integration test: Ed25519 authenticated handshakes.
#
# Hermetic: provisions its own throw-away keys and configs (lib.sh), so it
# never skips and never touches the developer's keys/ or config/.
#
#   1. All 6 nodes start with valid keys
#   2. The full mesh authenticates (every node authenticates all 5 peers)
#   3. An application frame sent right after authentication is delivered
#      (repeated: node 0 restarts 3 times; regression test for frames lost
#       when they arrive in the same read as HELLO_RESP)
#   4. A node whose key does not match the pinned pubkey refuses to start
#   5. Fail-closed: with NO pubkeys pinned, no peer is ever authenticated
#   6. SIGTERM shutdown is clean
#
# NOT TESTED here (reported as such, not as a pass): a network-level
# impostor that skips the local key check. That needs an injector tool.
#
# Ports 9000-9005 must be free on 127.0.0.1.
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
. tests/integration/lib.sh
provision "$TMP/fx" || { echo "cannot provision fixtures (is openssl installed?)"; exit 1; }
NET="$TMP/fx/network.conf"

# distinct authenticated peers seen in a log file
auth_count() {
    grep -o 'msg=peer_authenticated peer=[0-9]*' "$1" 2>/dev/null | sort -u | wc -l
}

# wait_for <seconds> <command...>: poll until the command succeeds
wait_for() {
    local secs=$1; shift
    for _ in $(seq 1 $((secs * 10))); do "$@" && return 0; sleep 0.1; done
    return 1
}

all_authenticated() {
    local i
    for i in 0 1 2 3 4 5; do
        [ "$(auth_count "$TMP/node_$i.log")" -eq 5 ] || return 1
    done
}

echo "== Test 1: all 6 nodes start with their keys"
for i in 0 1 2 3 4 5; do
    "$BIN" --network "$NET" --config "$TMP/fx/node_$i.conf" \
        >/dev/null 2>"$TMP/node_$i.log" </dev/null &
    PIDS[$i]=$!
done
started() { [ "$(grep -l 'msg=started' "$TMP"/node_*.log 2>/dev/null | wc -l)" -eq 6 ]; }
wait_for 5 started && pass "all 6 nodes started" || fail "not all nodes started"
n=$(grep -l 'msg=key_verified_against_network_conf' "$TMP"/node_*.log 2>/dev/null | wc -l)
[ "$n" -eq 6 ] && pass "all 6 loaded keys match the pinned pubkeys" \
               || fail "only $n/6 nodes verified their key against network.conf"

echo "== Test 2: the full mesh authenticates"
if wait_for 15 all_authenticated; then
    pass "every node authenticated all 5 peers"
else
    for i in 0 1 2 3 4 5; do
        echo "    node $i: $(auth_count "$TMP/node_$i.log")/5 authenticated"
    done
    fail "mesh did not fully authenticate within 15s"
fi

echo "== Test 3: frames sent right after authentication are delivered (3 restarts)"
for k in 1 2 3; do
    kill -TERM "${PIDS[0]}" 2>/dev/null
    wait_for 3 bash -c "! kill -0 ${PIDS[0]} 2>/dev/null" \
        || { kill -KILL "${PIDS[0]}" 2>/dev/null; fail "node 0 ignored SIGTERM (round $k)"; }
    wait "${PIDS[0]}" 2>/dev/null
    msg="phase3_hello_$k"
    "$BIN" --network "$NET" --config "$TMP/fx/node_0.conf" \
        --send-test 1 "$msg" >/dev/null 2>"$TMP/node_0_r$k.log" </dev/null &
    PIDS[0]=$!
    got() { grep -q "msg=recv_test.*$msg" "$TMP/node_1.log" 2>/dev/null; }
    wait_for 8 got && pass "round $k: node 1 received '$msg' from node 0" \
                   || fail "round $k: node 1 never received '$msg'"
done

echo "== Test 4: a node whose key does not match the pinned pubkey is refused"
openssl genpkey -algorithm ed25519 -out "$TMP/impostor.key" 2>/dev/null
sed "s|^key_path.*|key_path = $TMP/impostor.key|" "$TMP/fx/node_2.conf" > "$TMP/node_2_wrong_key.conf"
out=$(timeout 5 "$BIN" --network "$NET" --config "$TMP/node_2_wrong_key.conf" 2>&1 </dev/null); rc=$?
if [ "$rc" -eq 1 ] && grep -q 'msg=key_mismatch_with_network_conf' <<<"$out" \
   && ! grep -q 'msg=started' <<<"$out"; then
    pass "wrong key: exit 1, key_mismatch logged, node never started"
else
    fail "wrong key not rejected correctly (exit $rc): $out"
fi

echo "== Test 5: clean SIGTERM shutdown of the mesh"
for p in "${PIDS[@]}"; do kill -TERM "$p" 2>/dev/null; done
for i in 0 1 2 3 4 5; do
    wait "${PIDS[$i]}" 2>/dev/null; rc=$?
    lg="$TMP/node_$i.log"; [ "$i" -eq 0 ] && lg="$TMP/node_0_r3.log"
    [ "$rc" -eq 0 ] && grep -q 'msg=shutdown' "$lg" \
        && pass "node $i exited 0 and logged shutdown" \
        || fail "node $i rc=$rc / no shutdown log"
done
PIDS=()

echo "== Test 6: fail-closed when no pubkeys are pinned"
# Strip the pubkey field: nodes start (and warn) but must authenticate nobody.
awk '/^node /{print $1,$2,$3,$4,$5; next} {print}' "$NET" > "$TMP/nopub.conf"
for i in 0 1; do
    "$BIN" --network "$TMP/nopub.conf" --config "$TMP/fx/node_$i.conf" \
        >/dev/null 2>"$TMP/nopub_$i.log" </dev/null &
    PIDS[$i]=$!
done
sleep 3
authed=$(cat "$TMP"/nopub_*.log | grep -c 'msg=peer_authenticated')
refused=$(cat "$TMP"/nopub_*.log | grep -c 'no_pinned_key')
[ "$authed" -eq 0 ] && pass "no peer authenticated without pinned keys" \
                    || fail "$authed peers authenticated with NO pinned keys"
[ "$refused" -ge 1 ] && pass "handshake refused with a no_pinned_key event" \
                     || fail "no no_pinned_key event logged"
for p in "${PIDS[@]}"; do kill -TERM "$p" 2>/dev/null; done
for p in "${PIDS[@]}"; do wait "$p" 2>/dev/null; done
PIDS=()

echo
echo "NOT TESTED: network-level impostor (valid id, wrong key) - needs an injector tool."
if [ "$FAILED" -eq 0 ]; then
    echo "PHASE 3 INTEGRATION: ALL PASSED (1 item not tested, see above)"
else
    echo "PHASE 3 INTEGRATION: FAILURES"
fi
exit "$FAILED"
