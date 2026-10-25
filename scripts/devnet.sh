#!/usr/bin/env bash
# scripts/devnet.sh start|stop|status|wallet  - run the two-chain dev network from ./devnet
#
#   start                      2 validators per chain + 3 connectors (HTTP API 8080-8082)
#   stop                       stop everything started by 'start'
#   status                     which processes are alive, plus each connector's own view of its links
#   wallet <a|b> <to_hex|bridge> <amount> [fee]
#                              sign + submit one tx from that chain's dev wallet account
#                              ('bridge' = the chain's bridge escrow pubkey = cross-chain initiation)
# Env: UI_ORIGIN  CORS origin allowed by the connectors' HTTP API (default: null, for file:// pages)
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$(pwd)/devnet; RUN=$ROOT/run; LOGS=$ROOT/logs
NODE=bin/node; CONN=connector/bin/connector; WALLET=connector/bin/sc_wallet
ORIGIN=${UI_ORIGIN:-null}
[ -d "$ROOT" ] || { echo "run scripts/devnet_setup.sh first" >&2; exit 1; }
pub() { awk -v k="$1" '$1==k{print $2}' "$ROOT/pubkeys.txt"; }

alive() { [ -f "$RUN/$1.pid" ] && kill -0 "$(cat "$RUN/$1.pid")" 2>/dev/null; }
launch() { local name=$1; shift; setsid nohup "$@" >"$LOGS/$name.log" 2>&1 < /dev/null & echo $! > "$RUN/$name.pid"; }

case "${1:-}" in
start)
    for b in "$NODE" "$CONN" "$WALLET"; do [ -x "$b" ] || { echo "$b missing: run 'make' and 'make -C connector'" >&2; exit 1; }; done
    for c in a b; do for n in 0 1; do
        alive "chain_${c}_node$n" || launch "chain_${c}_node$n" "$NODE" --network "$ROOT/chain_$c/network.conf" --config "$ROOT/chain_$c/node_$n.conf"
    done; done
    sleep 2   # chains must be listening before connectors dial them
    for i in 0 1 2; do
        alive "connector$i" || launch "connector$i" "$CONN" --config "$ROOT/connectors/connector$i.conf" --http-port $((8080 + i)) --http-origin "$ORIGIN"
    done
    sleep 2
    "$0" status ;;
stop)
    for f in "$RUN"/*.pid; do [ -e "$f" ] || continue
        kill -TERM "$(cat "$f")" 2>/dev/null || true; rm -f "$f"
    done
    echo "stopped" ;;
status)
    for n in chain_a_node0 chain_a_node1 chain_b_node0 chain_b_node1 connector0 connector1 connector2; do
        alive $n && echo "up    $n" || echo "DOWN  $n"
    done
    for i in 0 1 2; do
        curl -s --max-time 2 "http://127.0.0.1:$((8080 + i))/api/status" | python3 -c "
import sys,json
try: d=json.load(sys.stdin)
except Exception: print('connector$i: HTTP API not answering'); sys.exit()
ch={c['id']:c['connected'] for c in d['chains']}
print('connector$i: chainA=%s chainB=%s peers_connected=%s/%s'%(ch['A'],ch['B'],d['peers']['connected'],d['peers']['configured']-1))" || true
    done ;;
wallet)
    c=${2:?chain a|b}; to=${3:?recipient hex or 'bridge'}; amt=${4:?amount}; fee=${5:-1}
    [ "$to" = bridge ] && to=$(pub "bridge_$c")
    base=9000; [ "$c" = b ] && base=19000
    nf="$RUN/wallet_$c.nonce"; nonce=$(cat "$nf" 2>/dev/null || echo 0)
    "$WALLET" --host 127.0.0.1 --port "$base" --node-id 5 --node-pubkey "$(pub chain_${c}_node0)" \
        --key "$ROOT/keys/wallet_$c.key" --to "$to" --amount "$amt" --fee "$fee" --nonce "$nonce" \
        && echo $((nonce + 1)) > "$nf" ;;
*) sed -n 2,10p "$0"; exit 2 ;;
esac
