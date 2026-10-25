#!/usr/bin/env bash
# scripts/test_devnet.sh - end-to-end check of the two-chain dev network (real processes, real sockets).
# Regenerates ./devnet (deletes its keys/data), starts everything, runs checks, stops everything.
# Needs: make && make -C connector, openssl, curl, python3.
set -uo pipefail
cd "$(dirname "$0")/.."
D=./scripts/devnet.sh; ROOT=$(pwd)/devnet
bash scripts/devnet_setup.sh --force >/dev/null || exit 1
trap '$D stop >/dev/null 2>&1' EXIT
$D start >/dev/null
fail=0; ok(){ echo "PASS $1"; }; bad(){ echo "FAIL $1"; fail=1; }
chk(){ [ "$2" = "$3" ] && ok "$1" || bad "$1 (got '$2', want '$3')"; }
api(){ curl -s --max-time 3 "127.0.0.1:$1$2"; }
j(){ python3 -c "import sys,json;d=json.load(sys.stdin);print($1)"; }
pub(){ awk -v k="$1" '$1==k{print $2}' "$ROOT/pubkeys.txt"; }

chk "7 processes up" "$($D status | grep -c '^up')" 7
for i in 0 1 2; do p=$((8080+i))
  chk "connector$i linked to chain A and B" "$(api $p /api/status | j '[c["connected"] for c in d["chains"]]')" "[True, True]"
  chk "connector$i peers connected" "$(api $p /api/status | j 'd["peers"]["connected"]')" 2
done
chk "topology has live links" "$(api 8080 /api/topology | j 'sum(l["live"] for l in d["links"])')" 4

$D wallet a "$(pub chain_a_node1)" 100 1 >/dev/null 2>&1
$D wallet b "$(pub chain_b_node1)" 250 1 >/dev/null 2>&1
sleep 4
for i in 0 1 2; do p=$((8080+i))
  chk "connector$i sees A tx and B tx" "$(api $p /api/activity | j 'sorted((r["source_chain"],r["amount"],r["type"]) for r in d["records"])')" "[('A', '100', 'same_chain'), ('B', '250', 'same_chain')]"
  chk "connector$i activity signatures valid" "$(api $p /api/activity | j 'all(r["reporter_signature_valid"] for r in d["records"])')" True
done
chk "ordinary txs created no transfers" "$(api 8080 /api/transfers | j 'd["total_matching"]')" 0
# visibility is not execution: the A-only amount (100) must never reach chain B's nodes, nor B's 250 chain A's
chk "A tx not mirrored to chain B" "$(cat devnet/logs/chain_b_node*.log | grep -c 'recv_tx.*amount=100 ')" 0
chk "B tx not mirrored to chain A" "$(cat devnet/logs/chain_a_node*.log | grep -c 'recv_tx.*amount=250 ')" 0

$D wallet a bridge 1000 1 >/dev/null 2>&1; sleep 5
chk "bridge tx classed cross_chain on every connector" "$(for p in 8080 8081 8082; do api $p "/api/activity?type=cross_chain" | j 'len(d["records"])'; done | tr '\n' ' ')" "1 1 1 "
chk "transfer A->B reached quorum" "$(api 8080 /api/transfers | j '(d["transfers"][0]["source_chain"],d["transfers"][0]["dest_chain"],d["transfers"][0]["approvals"]["count"]>=2)')" "('A', 'B', True)"

echo
echo "KNOWN GAPS in the supplied chain/connector (observed, not fixed here - see docs/DEVNET.md):"
echo "  - node daemons never propose DAG vertices, so nothing is ever finalized: activity status stays 'verified'"
echo "  - every connector independently submits its own destination tx (3x credit) to the escrow pubkey, not the user"
[ $fail = 0 ] && echo "ALL DEVNET TESTS PASSED" || { echo "SOME DEVNET TESTS FAILED"; exit 1; }
