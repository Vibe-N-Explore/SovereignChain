# tests/integration/lib.sh - hermetic fixtures for integration tests.
#
# provision <dir> creates a complete, throw-away 6-node setup:
#   <dir>/keys/nodeN.key   fresh Ed25519 private keys (mode 0600)
#   <dir>/network.conf     6-field lines with the matching pubkeys pinned
#   <dir>/node_N.conf      per-node config pointing at those keys
# Tests therefore never depend on (or modify) the developer's own keys/ and
# config/, and a fresh clone can run `make test` with no manual setup.
# Needs only the openssl CLI (no xxd).

provision() {
    local d=$1 i pub
    local roles=(validator validator normal normal normal normal)

    mkdir -p "$d/keys" "$d/data" || return 1
    : > "$d/network.conf"
    for i in 0 1 2 3 4 5; do
        openssl genpkey -algorithm ed25519 -out "$d/keys/node$i.key" 2>/dev/null \
            || { echo "provision: openssl genpkey failed" >&2; return 1; }
        chmod 600 "$d/keys/node$i.key"
        pub=$(openssl pkey -in "$d/keys/node$i.key" -pubout -outform DER 2>/dev/null \
              | tail -c 32 | od -An -tx1 | tr -d ' \n')
        [ "${#pub}" -eq 64 ] || { echo "provision: bad pubkey for node $i" >&2; return 1; }
        printf 'node %d %s 127.0.0.1 %d %s\n' "$i" "${roles[$i]}" "$((9000 + i))" "$pub" \
            >> "$d/network.conf"
        printf 'node_id  = %d\nkey_path = %s/keys/node%d.key\ndata_dir = %s/data/node%d\n' \
            "$i" "$d" "$i" "$d" "$i" > "$d/node_$i.conf"
    done
}
