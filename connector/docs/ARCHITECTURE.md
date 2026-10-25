# SovereignChain Connector Network Architecture

## 1. Overview & Purpose
The SovereignChain Connector Network bridges two independent SovereignChain instances (Chain A and Chain B). It performs two fundamental functions:
1. **Cross-Chain Activity Feed**: Observes native transactions on Chain A and Chain B, cryptographically attests to their observation, and propagates them as a unified feed.
2. **Cross-Chain Value Transfers**: Coordinates atomic value transfers from Chain A to Chain B (and vice-versa) using an escrow and credit mechanism secured by multi-connector consensus.

## 2. Cross-Chain Value Transfer Protocol (Escrow Model)
SovereignChain has no native bridge transaction opcodes. Cross-chain value transfer operates via **Escrow Accounts**:
- Each chain designates a **bridge escrow account public key** (`chain_a_bridge_pubkey` / `chain_b_bridge_pubkey`).
- To initiate a bridge transfer, a user sends an ordinary transaction on the source chain with `recipient = bridge_escrow_pubkey`.
- Connectors observe this transaction (`CN_TX_TYPE_CROSS_CHAIN`), verify its signature, and derive a deterministic `transfer_id`:
  $$\text{transfer\_id} = \text{SHA-256}(\text{"XFER/v1"} \parallel \text{source\_chain} \parallel \text{source\_tx\_hash})$$
- Connectors collect Ed25519 threshold signatures (votes). Once the configured `quorum` is reached, the transfer state becomes `CN_XFR_APPROVED`.
- An authorized connector issues a corresponding credit transaction on the destination chain to the user's recipient address.

## 3. Consensus & Quorum Model
- **Consensus Type**: Threshold multi-signature consensus (simple quorum threshold).
- **Vote Domain**:
  $$\text{vote\_hash} = \text{SHA-256}(\text{"XFER\_VOTE/v1"} \parallel \text{transfer\_id} \parallel \text{dest\_amount}_{\text{BE}} \parallel \text{rate\_version}_{\text{BE}})$$
- **Quorum Requirement**: At least `quorum` valid signatures from distinct registered connector peer keys.
- **Distinction from BFT**: This is an optimistic threshold signature validation mechanism among federated connectors, not Byzantine fault tolerance (BFT).

## 4. Trust Assumptions & Limitations
- **Light Observation**: The connector connects to full nodes of each chain as an authenticated client node. It validates Ed25519 signatures of received transactions (`tx_verify_sig`). It relies on chain node gossip and certificate broadcast rather than maintaining an independent full-chain state trie.
- **Identity Registration**: Each connector node's public key must be registered as a valid node ID in the chain's `network.conf`.
- **Escrow Solvency**: The connector network requires sufficient funds in the bridge credit account on each chain to fulfill bridge transfers.

## 5. Exchange Rate Management
- **Rational Arithmetic**: Exchange rates are expressed as integer ratios $\frac{\text{rate\_num}}{\text{rate\_den}}$. No floating-point operations are used.
  $$\text{dest\_amount} = \left\lfloor \frac{\text{source\_amount} \times \text{rate\_num}}{\text{rate\_den}} \right\rfloor$$
- **Overflow Safety**: Multiplications are computed using 128-bit unsigned arithmetic (`__uint128_t`) with bounds checks against $\text{UINT64\_MAX}$.
- **Rate Freezing**: When a transfer is detected, the applicable exchange rate is frozen in the transfer record so subsequent rate updates cannot alter an in-flight transfer.
- **Signed Updates**: Rate changes must be signed by connector keys and confirmed via `CN_MSG_RATE_VOTE` reaching quorum.

## 6. Persistence & Crash Recovery
- **Storage Directory**: All state is stored in `data_dir` using binary flat files:
  - `activity.dat`: Append-only activity records indexed by sequence numbers.
  - `transfers.dat`: Crash-safe atomic transfer state storage (written via `.tmp` and atomic `rename`).
  - `seen_ids.dat`: Fast deduplication index of 32-byte record IDs.
  - `rates.dat`: Persisted exchange rates.
- **Catch-up Sync**: When a connector restarts or reconnects, it sends `CN_MSG_SYNC_REQ` with its last known activity sequence number. Connected peers reply with `CN_MSG_SYNC_RESP` containing all subsequent records.
