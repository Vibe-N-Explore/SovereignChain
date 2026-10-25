/* tx.h - Transaction structure, serialization, signing, and verification.
 *
 * Phase 7: Deterministic Execution Engine.
 *
 * Transactions represent transfer of tokens between accounts:
 *   - sender: 32-byte Ed25519 public key
 *   - recipient: 32-byte Ed25519 public key
 *   - amount: uint64_t in base token units
 *   - fee: uint64_t transaction fee
 *   - nonce: uint64_t sender account sequence number (anti-replay)
 *   - signature: 64-byte Ed25519 signature over canonical payload
 *   - tx_hash: 32-byte SHA-256 identifier
 *
 * Canonical Signing Format (Domain Separator "TX/v1"):
 *   "TX/v1" (5 bytes)
 *   sender pubkey (32 bytes)
 *   recipient pubkey (32 bytes)
 *   amount (8 bytes, big-endian)
 *   fee (8 bytes, big-endian)
 *   nonce (8 bytes, big-endian)
 *   Total = 93 bytes
 */
#ifndef SC_TX_H
#define SC_TX_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "crypto.h"
#include "err.h"

#define SC_TX_PAYLOAD_LEN 93
#define SC_TX_WIRE_LEN    (32 + 32 + 8 + 8 + 8 + 64) /* 152 bytes */

typedef struct {
    uint8_t  sender[SC_ED25519_PUBKEY_LEN];
    uint8_t  recipient[SC_ED25519_PUBKEY_LEN];
    uint64_t amount;
    uint64_t fee;
    uint64_t nonce;
    uint8_t  sig[SC_ED25519_SIG_LEN];
    uint8_t  hash[SC_SHA256_LEN];
} sc_tx_t;

/* Create, sign, and hash a new transaction using sender_kp */
sc_err_t tx_create(sc_tx_t *tx, const sc_keypair_t *sender_kp,
                   const uint8_t recipient[SC_ED25519_PUBKEY_LEN],
                   uint64_t amount, uint64_t fee, uint64_t nonce);

/* Compute canonical signing payload (93 bytes) */
void tx_get_signing_bytes(const sc_tx_t *tx, uint8_t out[SC_TX_PAYLOAD_LEN]);

/* Verify the Ed25519 signature on an untrusted transaction */
sc_err_t tx_verify_sig(const sc_tx_t *tx);

/* Compute transaction hash (SHA-256 of canonical signing bytes) */
sc_err_t tx_compute_hash(const sc_tx_t *tx, uint8_t hash_out[SC_SHA256_LEN]);

/* Serialize transaction to binary wire format (152 bytes) */
sc_err_t tx_serialize(const sc_tx_t *tx, uint8_t *buf, size_t buflen, size_t *written_out);

/* Deserialize transaction from binary wire format */
sc_err_t tx_deserialize(sc_tx_t *tx, const uint8_t *buf, size_t buflen);

#endif /* SC_TX_H */
