# SovereignChain

**SovereignChain** is a C17 prototype combining a small authenticated
peer-to-peer blockchain, a simplified two-validator DAG consensus
mechanism, a deterministic account ledger, and a federated connector
network for cross-chain activity and transfer coordination.

This repository contains two related systems:

1.  **The chain node** --- transaction validation and gossip, DAG
    vertices, validator voting/certification, ledger execution, and
    persisted state.
2.  **The connector network** --- observes transactions on Chain A and
    Chain B, publishes a unified activity feed, coordinates transfer
    approvals among connectors, and exposes a read-only HTTP API.

> **Prototype notice:** this is a local development project, not a
> production bridge or a Byzantine-fault-tolerant blockchain. Read
> [Security model and known
> limitations](#security-model-and-known-limitations) before using it
> with anything valuable.

## Contents

-   [Architecture](#architecture)
-   [Repository layout](#repository-layout)
-   [Requirements](#requirements)
-   [Build](#build)
-   [Run the six-node chain harness](#run-the-six-node-chain-harness)
-   [Run the two-chain connector
    devnet](#run-the-two-chain-connector-devnet)
-   [Make a development wallet
    transaction](#make-a-development-wallet-transaction)
-   [Connector HTTP API](#connector-http-api)
-   [Tests](#tests)
-   [Configuration and persistence](#configuration-and-persistence)
-   [Transaction and transfer
    lifecycle](#transaction-and-transfer-lifecycle)
-   [Troubleshooting](#troubleshooting)
-   [Development notes](#development-notes)

## Architecture

### Chain node

The chain implementation is written in C17 and uses POSIX networking and
OpenSSL. Its major subsystems are:

-   **Configuration and process lifecycle:** loads network and per-node
    configuration, checks the configured topology, and handles shutdown.
-   **Networking:** framed TCP messages, a `poll()`-based event loop,
    peer reconnection, and transaction/vertex/vote propagation.
-   **Cryptography:** Ed25519 signatures and SHA-256 hashing through
    OpenSSL.
-   **Transactions and mempool:** transaction serialization and
    signature checks, validation, deduplication, batching, and gossip.
-   **DAG:** creates, validates, hashes, stores, and references
    vertices.
-   **SPD consensus prototype:** two-validator certification,
    alternating anchors, equivocation checks, and deterministic
    ordering.
-   **Ledger:** deterministic account-state updates, balances, nonces,
    fees, and state-root hashing.
-   **Persistence:** checksummed state snapshots and crash-recovery
    support.

The root `config/` is the six-node harness described in the existing
project docs: two validator roles and four normal-node identities. The
local launcher starts six processes on the configured localhost ports.

### Connector network

The connector is a separate process and has its own connector identity,
peer network, persistent records, transfer state, exchange-rate
configuration, and HTTP API. In the supplied devnet configuration, three
connectors form a network with a quorum threshold of two.

Each connector connects to one configured node endpoint on Chain A and
one on Chain B. It observes chain transactions, verifies transaction
signatures, creates signed activity records, shares records with its
connector peers, and identifies transactions addressed to a configured
bridge escrow key as cross-chain transfer candidates.

The connector API is **read-only**: it reports status, topology,
activity, transfers, and configured rates. It is not a public
transaction-submission API.

### Cross-chain model

The documented model is escrow-based:

1.  A user sends an ordinary transaction on the source chain to that
    chain's configured bridge escrow public key.
2.  Connectors detect the transaction and derive a deterministic
    transfer ID from the source chain and source transaction hash.
3.  Connectors calculate the destination amount using the frozen integer
    exchange-rate ratio and exchange signed transfer votes.
4.  A transfer is approved when the configured connector quorum is
    reached.
5.  The connector implementation can submit a corresponding transaction
    to the destination chain.

**Important:** connector quorum approval, destination transaction
submission, destination-chain consensus finality, and successful
recipient credit are different events. The current source has
implementation gaps around destination-recipient selection and
completion tracking; see [Security model and known
limitations](#security-model-and-known-limitations). Do not interpret a
transfer's `COMPLETED` label as proof of a correct end-to-end transfer
until those gaps have been fixed and tested.

## Repository layout

``` text
.
├── Makefile                    # Chain build and test targets
├── config/                     # Six-node chain harness configuration
├── src/
│   ├── main.c                  # Chain-node event loop and callbacks
│   ├── config.*                # Configuration loading/validation
│   ├── net.*                   # TCP peer networking and framing
│   ├── crypto.*                # Ed25519 and SHA-256 helpers
│   ├── tx.*                    # Transaction representation/serialization
│   ├── mempool.*               # Transaction validation, batching, deduplication
│   ├── dag.*                   # DAG vertex representation and storage
│   ├── consensus.*             # Validator voting and certification
│   ├── ledger.*                # Deterministic account ledger
│   └── storage.*               # Persistent chain state
├── tests/
│   ├── unit/                   # Chain unit tests
│   └── integration/            # Multi-process integration tests
├── scripts/
│   ├── run_local.sh            # Start the six-node local harness
│   ├── devnet_setup.sh         # Generate fresh devnet keys/configuration
│   ├── devnet.sh               # Start/stop/status/wallet commands
│   ├── test_devnet.sh          # Connector devnet smoke checks
│   └── keygen.sh               # Key-generation helper
├── docs/DEVNET.md              # Existing two-chain devnet notes
└── connector/
    ├── Makefile                # Connector build and tests
    ├── src/                    # Connector networking, chain client, transfer/API code
    ├── config/                 # Example connector configurations
    ├── docs/
    │   ├── ARCHITECTURE.md     # Connector architecture notes
    │   └── HTTP_API.md         # API endpoint reference
    ├── tests/                  # Connector unit tests and HTTP smoke test
    └── scripts/keygen.sh       # Connector key helper
```

The archive also contains `bin/`, `connector/bin/`, and `devnet/`
runtime artifacts from a previous local run. The `devnet/` directory
contains private keys, state files, logs, and process metadata; treat
those keys as development-only and regenerate them before a fresh run.
The supplied archive does **not** contain a standalone
HTML/CSS/JavaScript dashboard, despite the API being suitable for a
local UI.

## Requirements

The documented build environment is Linux or WSL with:

-   GCC or Clang with C17 support
-   GNU Make
-   OpenSSL development headers and libraries
-   `pkg-config` (recommended; the Makefiles fall back to
    `-lssl -lcrypto`)
-   `bash`
-   Python 3, `curl`, `openssl`, and `od` for devnet scripts/tests
-   `xxd` for the root key-generation helper, if used

On Debian/Ubuntu/WSL, install the main dependencies with:

``` bash
sudo apt update
sudo apt install build-essential libssl-dev pkg-config python3 curl openssl
```

If a script reports a missing utility, install that utility using your
distribution's package manager.

## Build

Run these commands from the repository root:

``` bash
make
make -C connector
```

The root build produces:

-   `bin/node`
-   `bin/injector`

The connector build produces:

-   `connector/bin/connector`
-   `connector/bin/sc_wallet`

The Makefiles use C17 and compile with `-Wall -Wextra -Werror`.
Unit-test builds enable AddressSanitizer and UndefinedBehaviorSanitizer
when the compiler supports them.

## Run the six-node chain harness

Build the chain binaries, then run:

``` bash
./scripts/run_local.sh
```

This starts six local node processes using `config/network.conf` and
`config/node_0.conf` through `config/node_5.conf`. Logs are written to
`logs/node_<id>.log`. Press **Ctrl-C** to request shutdown.

This harness is distinct from the two-chain connector devnet described
below. It is useful for exercising the chain-node network and consensus
components in isolation.

## Run the two-chain connector devnet

### 1. Build both components

``` bash
make
make -C connector
```

### 2. Generate fresh development configuration

``` bash
bash scripts/devnet_setup.sh
```

The script creates `devnet/` with fresh Ed25519 keys, chain and
connector configurations, storage directories, and public-key listings.
If `devnet/` already exists, the script refuses to overwrite it. To
deliberately regenerate the devnet:

``` bash
bash scripts/devnet_setup.sh --force
```

**Warning:** `--force` deletes the existing `devnet/` directory,
including its keys and chain data. Stop running devnet processes first
and back up anything you need.

### 3. Start the devnet

``` bash
./scripts/devnet.sh start
./scripts/devnet.sh status
```

The supplied scripts configure this local topology:

  Component                    Count Default ports
  -------------------------- ------- -------------------------
  Chain A validators               2 `127.0.0.1:9000–9001`
  Chain B validators               2 `127.0.0.1:19000–19001`
  Connector peer listeners         3 `127.0.0.1:8000–8002`
  Connector HTTP APIs              3 `127.0.0.1:8080–8082`

The scripts start seven processes in total: two validators for each
chain and three connectors. The four additional configured node
identities per chain are pinned identities used for connector/wallet
authentication in this devnet setup; the devnet script does not start
those as full chain-node processes.

The HTTP API's allowed CORS origin defaults to `null`, intended for a
page opened using `file://`. If a local page is served from an HTTP
origin, set `UI_ORIGIN` to that exact origin when starting the devnet,
for example:

``` bash
UI_ORIGIN=http://127.0.0.1:5500 ./scripts/devnet.sh start
```

Stop the devnet with:

``` bash
./scripts/devnet.sh stop
```

Check `devnet/logs/` if a process does not start. Do not commit
generated private keys or use them outside local development.

## Make a development wallet transaction

The `devnet.sh wallet` helper uses the development wallet key generated
for the chosen chain:

``` bash
# Ordinary transaction on Chain A to a recipient public key (64 hex characters)
./scripts/devnet.sh wallet a <recipient_pubkey_hex> 100

# Ordinary transaction on Chain B
./scripts/devnet.sh wallet b <recipient_pubkey_hex> 250

# Send to the configured bridge escrow to create a cross-chain candidate
./scripts/devnet.sh wallet a bridge 1000
```

The optional fifth argument is the fee; the script defaults it to `1`.
The helper tracks its development wallet nonce under `devnet/run/`. The
`bridge` keyword substitutes the configured bridge escrow public key for
the selected source chain.

These are development commands. Before testing a bridge transfer, ensure
the network is freshly configured and running, record the
source/destination state, and verify the destination recipient and
balances independently. A connector activity record or a quorum-approved
transfer alone is not evidence that the recipient was correctly
credited.

## Connector HTTP API

Each connector exposes its own read-only API when started with the HTTP
listener enabled. The devnet launcher enables it on ports `8080`,
`8081`, and `8082`.

Example requests:

``` bash
curl -s http://127.0.0.1:8080/api/status
curl -s http://127.0.0.1:8080/api/topology
curl -s 'http://127.0.0.1:8080/api/activity?limit=50'
curl -s http://127.0.0.1:8080/api/transfers
curl -s http://127.0.0.1:8080/api/rates
```

The documented endpoints are:

  ------------------------------------------------------------------------
  Endpoint                             Purpose
  ------------------------------------ -----------------------------------
  `GET /api/status`                    Connector identity, quorum, chain
                                       connection state, peer
                                       connectivity, activity and transfer
                                       counts

  `GET /api/topology`                  Configured nodes and links; a link
                                       is live only when the corresponding
                                       authenticated connection is live

  `GET /api/activity`                  Paginated activity feed; supports
                                       chain, type, status, sequence
                                       cursor, and limit filters

  `GET /api/activity/{record_id}`      Fetch one activity record by
                                       64-character hexadecimal record ID

  `GET /api/transfers`                 Paginated transfer list; supports
                                       state, source-chain, offset, and
                                       limit filters

  `GET /api/transfers/{transfer_id}`   Fetch one transfer by 64-character
                                       hexadecimal transfer ID

  `GET /api/rates`                     Current A-to-B and B-to-A rational
                                       rates and their signature/validity
                                       metadata
  ------------------------------------------------------------------------

Full query parameters and response semantics are documented in
[`connector/docs/HTTP_API.md`](connector/docs/HTTP_API.md).

Security behavior documented in the API implementation:

-   The HTTP API accepts `GET` and `OPTIONS`; state-changing methods are
    rejected.
-   It binds to loopback by default.
-   A loopback request with an unexpected `Host` header is rejected as a
    DNS-rebinding guard.
-   CORS echoes only the configured exact origin; wildcards are
    rejected.
-   Non-loopback binding has no API authentication and should not be
    exposed to an untrusted network.

Large numeric values are represented as decimal strings in JSON to avoid
precision loss in clients that use IEEE-754 numbers. The activity
record's reporter signature validates the reporting connector's
attestation and record-ID derivation; it is **not** itself proof of
source-chain finality.

## Tests

### Chain unit tests

``` bash
make test-unit
```

### Chain integration tests

``` bash
make test-integration
```

The integration target runs the phase scripts in `tests/integration/`.
They start real local processes and exercise configuration,
authenticated networking, transaction propagation, DAG/consensus,
execution, persistence, and adversarial cases as represented by the
tests.

### Run both chain test groups

``` bash
make test
```

### Connector unit tests

``` bash
make -C connector test
```

### Connector/devnet smoke test

``` bash
bash scripts/test_devnet.sh
```

**Caution:** the devnet smoke script regenerates `devnet/` with
`--force` and then starts/stops processes. It deletes the existing
devnet keys and chain data. Do not run it against data you need to keep.

The supplied smoke test checks process startup, connector connectivity,
topology links, activity observation/signatures, ordinary transaction
isolation, and transfer quorum approval. It does **not** establish
correct destination-recipient credit or independently prove
destination-chain finality.

## Configuration and persistence

### Chain configuration

-   `config/network.conf` defines the network's pinned node identities
    and endpoints.
-   `config/node_<id>.conf` sets each node's ID, private-key path, and
    data directory.
-   The devnet setup script generates separate files under
    `devnet/chain_a/` and `devnet/chain_b/`.

### Connector configuration

-   `connector/config/connector*.conf` are example connector configs.
-   `devnet/connectors/connector*.conf` are generated for the local
    two-chain environment.
-   Connector config includes connector identity/key path, persistent
    data directory, peer endpoints and public keys, chain endpoints and
    pinned public keys, bridge escrow public keys, quorum, and rational
    exchange-rate values.

Prefer `scripts/devnet_setup.sh` to create fresh, internally consistent
development configuration instead of editing generated keys and public
keys manually.

### Data files

Connector storage uses the configured `data_dir`. The architecture notes
describe:

-   `activity.dat` --- persisted activity records
-   `seen_ids.dat` --- deduplication index for record IDs
-   `transfers.dat` --- persisted transfer state
-   `rates.dat` --- persisted exchange rates

The devnet also creates chain node state directories and logs. Keep
generated state separate from source-controlled configuration. Back up
data before manually deleting it or regenerating the devnet.

## Transaction and transfer lifecycle

### Same-chain transaction

1.  A wallet signs a transaction with its Ed25519 key.
2.  The transaction is submitted to a chain node.
3.  The node validates and adds it to the mempool.
4.  Nodes gossip the transaction.
5.  Validators propose DAG vertices containing batches of pending
    transactions and exchange votes/certificates according to the
    consensus implementation.
6.  The ledger executes committed transactions in deterministic order
    and persists state.

### Cross-chain transfer (intended flow)

1.  A source-chain transaction sends value to the source chain's
    configured escrow public key.
2.  Connectors observe the transaction and classify it as a cross-chain
    candidate.
3.  A deterministic transfer ID is derived from the source chain and
    source transaction hash.
4.  Connectors calculate the destination amount using the transfer's
    recorded integer rate ratio.
5.  Connectors exchange signatures over transfer data; distinct valid
    peer signatures count toward the configured quorum.
6.  The transfer is marked approved when quorum is reached.
7.  A connector submits a destination-chain credit transaction.
8.  The destination transaction must be included in a destination-chain
    certificate/commit before the transfer can be treated as executed.

Steps 7--8 require the correctness conditions described below; the
current source does not yet enforce them safely.


## Troubleshooting

**`bin/node` or `connector/bin/connector` is missing**

``` bash
make
make -C connector
```

**The devnet setup script says `devnet/` already exists**

Stop the processes first. If you are sure the existing keys/data can be
deleted, regenerate with:

``` bash
bash scripts/devnet_setup.sh --force
```

**A process is down or a port is already in use**

``` bash
./scripts/devnet.sh status
tail -n 100 devnet/logs/chain_a_node0.log
tail -n 100 devnet/logs/connector0.log
```

Change the generated configuration only if you also keep all
corresponding endpoints and pinned keys consistent.

**Connector HTTP requests fail**

Check `./scripts/devnet.sh status`, the connector log, the HTTP port,
and `--http-origin`/`UI_ORIGIN`. A `file://` page sends the origin
`null`; a page served over HTTP needs its exact origin configured.

**A transfer appears approved but balances do not reflect the intended
transfer**

Approval means connector quorum, not successful destination execution.
Inspect the transfer record, destination transaction hash, destination
chain logs/state, and recipient key. See [Cross-chain correctness
gaps](#cross-chain-correctness-gaps-found-in-this-archive).

## Development notes

-   Keep changes small and run the relevant unit and integration tests
    after modifying protocol or storage code.
-   When changing serialized structs or on-disk formats, account for
    compatibility with existing devnet state; use a fresh devnet for
    tests that require clean state.
-   Do not treat successful compilation or a smoke test as proof of
    end-to-end bridge correctness.
-   Update `connector/docs/HTTP_API.md`,
    `connector/docs/ARCHITECTURE.md`, and `docs/DEVNET.md` when behavior
    changes, and make sure those docs agree with the source and tests.
-   Before publishing a ZIP, exclude generated private keys, state
    files, logs, PIDs, and build artifacts. Include source,
    configuration templates, scripts, tests, and documentation instead.

