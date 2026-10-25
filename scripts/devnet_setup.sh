#!/usr/bin/env bash
# scripts/devnet_setup.sh - generate a complete two-chain development network in ./devnet
#
#   Chain A: validators 0,1 on 127.0.0.1:9000,9001      Chain B: validators 0,1 on :19000,19001
#   Each chain's network.conf keeps the fixed 2-validator + 4-normal topology. The four normal
#   slots (ids 2..5) are NOT full nodes here: they are identities pinned for the connectors
#   (ids 2,3,4 = connector 0,1,2) and a dev wallet (id 5), because a chain node only accepts
#   clients whose pubkey is pinned in its network.conf. Node processes 2..5 are not started.
#   Genesis (existing behaviour) credits every pinned pubkey with 1,000,000 tokens.
#   3 connectors, quorum 2, peers on 8000-8002, HTTP API on 8080-8082 (see devnet.sh).
#
# Usage: bash scripts/devnet_setup.sh [--force]     (needs: openssl, od)
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$(pwd)/devnet
if [ -e "$ROOT" ]; then
    [ "${1:-}" = "--force" ] || { echo "devnet/ already exists; run with --force to regenerate (this deletes its keys and chain data)" >&2; exit 1; }
    rm -rf "$ROOT"
fi
mkdir -p "$ROOT"/{keys,chain_a,chain_b,connectors,logs,run}
chmod 700 "$ROOT/keys"

genkey() {  # genkey <name>  -> keys/<name>.key ; pubkey hex in PUB[<name>]
    local f="$ROOT/keys/$1.key"
    openssl genpkey -algorithm ed25519 -out "$f" 2>/dev/null
    chmod 600 "$f"
    PUB[$1]=$(openssl pkey -in "$f" -pubout -outform DER 2>/dev/null | tail -c 32 | od -An -tx1 | tr -d ' \n')
    [ "${#PUB[$1]}" -eq 64 ] || { echo "bad pubkey for $1" >&2; exit 1; }
}
declare -A PUB
for c in a b; do for n in 0 1; do genkey "chain_${c}_node$n"; done; genkey "bridge_$c"; genkey "wallet_$c"; done
for i in 0 1 2; do genkey "connector$i"; done

# slot id -> pubkey name (same connector keys are pinned on BOTH chains)
slot_key() { case $2 in 0|1) echo "chain_${1}_node$2";; 2|3|4) echo "connector$(( $2 - 2 ))";; 5) echo "wallet_$1";; esac; }
roles=(validator validator normal normal normal normal)

for c in a b; do
    base=9000; [ $c = b ] && base=19000
    : > "$ROOT/chain_$c/network.conf"
    for id in 0 1 2 3 4 5; do
        printf 'node %d %s 127.0.0.1 %d %s\n' "$id" "${roles[$id]}" "$((base + id))" "${PUB[$(slot_key $c $id)]}" >> "$ROOT/chain_$c/network.conf"
    done
    for id in 0 1; do
        mkdir -p "$ROOT/chain_$c/data/node$id"
        printf 'node_id  = %d\nkey_path = %s/keys/chain_%s_node%d.key\ndata_dir = %s/chain_%s/data/node%d\n' \
            "$id" "$ROOT" "$c" "$id" "$ROOT" "$c" "$id" > "$ROOT/chain_$c/node_$id.conf"
    done
done

for i in 0 1 2; do
    mkdir -p "$ROOT/connectors/data$i"
    {
        echo "connector_id = $i"
        echo "key_path     = $ROOT/keys/connector$i.key"
        echo "data_dir     = $ROOT/connectors/data$i"
        echo "listen_host  = 127.0.0.1"
        echo "listen_port  = $((8000 + i))"
        echo "quorum       = 2"
        echo "log_level    = 1"
        # connector i dials chain validator (i mod 2) and identifies as pinned slot 2+i
        echo "chain_a_host          = 127.0.0.1"
        echo "chain_a_port          = $((9000 + i % 2))"
        echo "chain_a_pubkey        = ${PUB[chain_a_node$((i % 2))]}"
        echo "chain_a_node_id       = $((2 + i))"
        echo "chain_a_bridge_pubkey = ${PUB[bridge_a]}"
        echo "chain_b_host          = 127.0.0.1"
        echo "chain_b_port          = $((19000 + i % 2))"
        echo "chain_b_pubkey        = ${PUB[chain_b_node$((i % 2))]}"
        echo "chain_b_node_id       = $((2 + i))"
        echo "chain_b_bridge_pubkey = ${PUB[bridge_b]}"
        echo "rate_a_to_b_num = 1"; echo "rate_a_to_b_den = 1"
        echo "rate_b_to_a_num = 1"; echo "rate_b_to_a_den = 1"
        for p in 0 1 2; do echo "peer $p 127.0.0.1 $((8000 + p)) ${PUB[connector$p]}"; done
    } > "$ROOT/connectors/connector$i.conf"
done
# machine-readable pubkeys (public information) for scripts and the test harness
for k in "${!PUB[@]}"; do echo "$k ${PUB[$k]}"; done | sort > "$ROOT/pubkeys.txt"
echo "devnet generated in $ROOT"
echo "  chain A bridge escrow: ${PUB[bridge_a]}"
echo "  chain B bridge escrow: ${PUB[bridge_b]}"
