#!/usr/bin/env bash
# connector/scripts/keygen.sh - Generate Ed25519 keypairs for connectors and bridge escrow accounts.
#
# Generates:
#   connector/keys/connector0.key (and pubkey)
#   connector/keys/connector1.key (and pubkey)
#   connector/keys/connector2.key (and pubkey)
#   connector/keys/bridge_a.key   (and pubkey)
#   connector/keys/bridge_b.key   (and pubkey)
set -euo pipefail
cd "$(dirname "$0")/.."

mkdir -p keys
chmod 700 keys

echo "=== Generating Connector Keys ==="
echo

for i in 0 1 2; do
    keyfile="keys/connector${i}.key"
    openssl genpkey -algorithm ed25519 -out "$keyfile" 2>/dev/null
    chmod 600 "$keyfile"

    pubhex=$(openssl pkey -in "$keyfile" -pubout -outform DER 2>/dev/null \
             | tail -c 32 | xxd -p | tr -d '\n')
    echo "Connector $i:"
    echo "  Private key: $keyfile"
    echo "  Public key:  $pubhex"
    echo
done

echo "=== Generating Bridge Escrow Accounts ==="
echo

for chain in a b; do
    keyfile="keys/bridge_${chain}.key"
    openssl genpkey -algorithm ed25519 -out "$keyfile" 2>/dev/null
    chmod 600 "$keyfile"

    pubhex=$(openssl pkey -in "$keyfile" -pubout -outform DER 2>/dev/null \
             | tail -c 32 | xxd -p | tr -d '\n')
    echo "Bridge Escrow Chain $chain:"
    echo "  Private key: $keyfile"
    echo "  Public key:  $pubhex"
    echo
done

echo "Done. Configure these pubkeys in connector/config/connector*.conf"
