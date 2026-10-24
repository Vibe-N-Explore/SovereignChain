# SovereignChain (C17 prototype)

Development harness: 6 node processes on localhost (2 validators + 4 normal).
This is NOT a decentralized deployment and NOT Byzantine fault tolerant
(2 validators => f = 0).

## Requirements
Linux/WSL, gcc or clang (C17), make. (OpenSSL dev package is needed from Phase 3:
`sudo apt install build-essential libssl-dev`.)

## Build / test / run
    make                 # builds bin/node (-Wall -Wextra -Werror)
    make test-unit       # unit tests, built with ASan + UBSan
    make test-integration  # starts 6 real processes on ports 9000-9005
    make test            # both
    ./scripts/run_local.sh   # start all 6 nodes; logs in logs/; Ctrl-C stops

## Status
| Phase | Item | Status |
|---|---|---|
| 1 | Config parsing, role lookup, fixed 2+4 topology, structured log, listen socket, clean shutdown | implemented + tested |
| 1 | key_path is parsed but the key file is not read or checked yet | deferred to Phase 3 |
| 2-9 | networking, crypto, transactions, DAG, consensus, execution, persistence, security tests | not started |
| - | TLS, TCB process, ZK, AI agents (in the PDF, not in the phase list) | deferred |
