# Two-chain development network

    make && make -C connector            # needs libssl-dev, pkg-config
    bash scripts/devnet_setup.sh         # generates ./devnet (keys, configs); --force to regenerate
    ./scripts/devnet.sh start            # 2 validators per chain + 3 connectors, detached
    ./scripts/devnet.sh status
    ./scripts/devnet.sh wallet a <recipient_hex> 100     # ordinary tx on chain A (b for chain B)
    ./scripts/devnet.sh wallet a bridge 1000             # cross-chain initiation (send to A's escrow)
    ./scripts/devnet.sh stop
    ./scripts/test_devnet.sh             # full automated check (regenerates devnet)

Layout: Chain A nodes 127.0.0.1:9000-9001, Chain B 19000-19001, connector peers 8000-8002,
connector HTTP APIs 8080-8082 (`UI_ORIGIN` sets the allowed CORS origin, default `null` for file:// pages).
Logs: `devnet/logs/`. Keys are in `devnet/keys/` (git-ignored; dev use only).

## Design constraints
- `config_check_topology` forces exactly 2 validators + 4 normal nodes per chain, and a chain node only
  accepts clients whose pubkey is pinned in its network.conf. So the four "normal" slots (ids 2-5) are
  pinned identities, not running nodes: ids 2,3,4 = connectors 0,1,2 (same keys on both chains),
  id 5 = dev wallet. Chains run on their two validators only.
- Existing genesis behaviour credits every pinned pubkey with 1,000,000 tokens (connectors and wallet included).
- `sc_wallet` (connector/src/sc_wallet.c) signs and submits one tx using a key file. Dev tool; the key is
  read from disk and never printed. `devnet.sh wallet` tracks the nonce in `devnet/run/wallet_<chain>.nonce`.

## Verified (scripts/test_devnet.sh, 19 checks, all pass)
Both chains up; every connector linked to both chains and to both peers; ordinary txs on A and on B appear
on all three connectors with valid reporter signatures; they create no transfer and are not gossiped to the
other chain's nodes; a tx to the bridge escrow is classified cross_chain and a transfer A->B reaches quorum.

## Gaps found in the supplied system (not changed)
1. **Nothing is ever finalized.** `vertex_create` and `mempool_get_batch` exist, but the node daemon
   (`src/main.c`) never proposes vertices, so transactions stay in mempools; no certificates or commits occur.
   Activity stays `verified`; state roots never change.
2. **Destination credit is wrong and triplicated.** Every connector independently submits its own destination
   tx (signed with its own key) crediting `transfer.recipient`, which is the *source escrow pubkey*
   (the tx's only recipient), not the user. With 3 connectors that is three credits per transfer.
3. **Premature completion.** The cert callback moves every `DESTINATION_SUBMITTED` transfer to `COMPLETED`
   on any certificate without checking that it covers the destination tx.
4. Chain-level balances cannot be queried (no ledger read interface), so "balance changed / did not change"
   can only be inferred from logs today.
