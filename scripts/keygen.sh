#!/usr/bin/env bash
# scripts/keygen.sh - Generate Ed25519 keypairs for all 6 SovereignChain nodes.
#
# What this does:
#   1. Generates keys/nodeN.key (PEM private key, mode 0600) for each node
#   2. Prints the 64-char hex public key for each node
#   3. Writes a ready-to-paste network.conf snippet with pubkeys embedded
#
# Usage (from repo root):
#   bash scripts/keygen.sh
#
# After running, paste the printed network.conf lines into config/network.conf.
#
# SECURITY NOTE: Private key files (keys/nodeN.key) must NEVER be committed
# to version control. The .gitignore already excludes keys/. Each node
# should only have its own private key.
set -euo pipefail
cd "$(dirname "$0")/.."

mkdir -p keys
chmod 700 keys

NETWORK_CONF="config/network.conf"

# Read the existing network.conf to get the role/host/port for each node
# Format: node <id> <role> <host> <port> [old_pubkey]
declare -A ROLES HOSTS PORTS
while read -r _ id role host port _rest; do
    [[ "$_" == "#"* ]] && continue  # skip comment-only lines (handled below)
    ROLES[$id]=$role
    HOSTS[$id]=$host
    PORTS[$id]=$port
done < <(grep '^node ' "$NETWORK_CONF")

echo "Generating Ed25519 keypairs for nodes 0-5..."
echo

declare -A PUBKEYS

for i in 0 1 2 3 4 5; do
    keyfile="keys/node${i}.key"

    # Generate private key using openssl command line
    # 'genpkey' generates a private key in PEM format
    openssl genpkey -algorithm ed25519 -out "$keyfile" 2>/dev/null
    chmod 600 "$keyfile"

    # Extract the raw 32-byte public key as hex.
    # 'pkey -pubout -outform DER' gives us DER-encoded SubjectPublicKeyInfo.
    # The last 32 bytes of an Ed25519 SPKI are the raw public key.
    # We use tail -c 32 | xxd to get just those bytes as hex.
    pubhex=$(openssl pkey -in "$keyfile" -pubout -outform DER 2>/dev/null \
             | tail -c 32 | xxd -p | tr -d '\n')

    PUBKEYS[$i]=$pubhex
    echo "  node $i: key=${keyfile}  pubkey=${pubhex}"
done

echo
echo "=========================================="
echo "  New config/network.conf content:"
echo "=========================================="
echo "# SovereignChain development network (single host, localhost ports)."
echo "# This is a test harness, NOT a decentralized deployment."
echo "#"
echo "# node <id> <validator|normal> <ipv4-address> <port> <ed25519_pubkey_hex>"
echo "#"
echo "# Fixed topology: 2 validators + 4 normal nodes."
for i in 0 1 2 3 4 5; do
    printf "node %d %s %s %s %s\n" \
        "$i" "${ROLES[$i]}" "${HOSTS[$i]}" "${PORTS[$i]}" "${PUBKEYS[$i]}"
done

echo
echo "Copy the above into config/network.conf"
echo
echo "REMINDER: Never commit keys/nodeN.key to version control!"
