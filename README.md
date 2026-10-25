# SovereignChain (C17 prototype)

Development harness: 6 node processes on localhost (2 validators + 4 normal).
This is NOT a decentralized deployment and NOT Byzantine fault tolerant
(2 validators => f = 0).

## Requirements
Linux/WSL, gcc or clang (C17), make. (OpenSSL dev package is needed from Phase 3:
`sudo apt install build-essential libssl-dev pkg-config`; `scripts/keygen.sh` also needs `xxd`.)
Integration tests provision their own temporary keys; no manual setup needed for `make test`.

## Build / test / run
    make                 # builds bin/node (-Wall -Wextra -Werror)
    make test-unit       # unit tests, built with ASan + UBSan
    make test-integration  # starts 6 real processes on ports 9000-9005
    make test            # both
    ./scripts/run_local.sh   # start all 6 nodes; logs in logs/; Ctrl-C stops

## Status
| Phase | Item | Status |
|---|---|---|
| 1 | Config, roles, fixed 2+4 topology, logging, clean shutdown | implemented + unit and integration tested |
| 2 | Framed TCP, poll() loop, reconnection | implemented; exercised via mesh connections |
| 3 | Ed25519 identities, pinned pubkeys, challenge-response handshake | implemented; mesh auth, wrong-key refusal, fail-closed and post-handshake delivery tested |
| 4 | Transactions format, mempool validation, deduplication, batching, gossip | implemented + unit and integration tested |
| 5 | DAG construction, vertices, parent references, VERTEX/v1 canonical hashing, storage | implemented + unit and integration tested |
| 6 | SPD Consensus: 2-of-2 certification, alternating anchors, commit rule, equivocation detection, deterministic ordering | implemented + unit and integration tested |
| 7 | Deterministic execution engine: account ledger, token transfers, nonces, canonical state root hashing (SHA-256) | implemented + unit and integration tested |
| 8 | Atomic persistence and crash recovery: checksummed state.dat, atomic fsync+rename, tamper rejection | implemented + unit and integration tested |
| 9 | Security & adversarial testing: network impostor injection, DoS oversized frame rejection, replay attack, double-spend, overflow checks | implemented + unit and integration tested |
| - | TLS, TCB process, ZK, AI agents | deferred |

Known Phase 3 design issues (not yet fixed): handshake signs the raw nonce with no
domain separation; the listener authenticates itself by signing its OWN nonce (the
connector contributes no challenge, so that half is replayable); frames after the
handshake are not authenticated or encrypted.
