/* cn_transfer.h - Cross-chain transfer state machine and arithmetic. */
#ifndef CN_TRANSFER_H
#define CN_TRANSFER_H

#include "connector_types.h"

/* Compute transfer_id: SHA-256("XFER/v1" || source_chain(1) || source_tx_hash(32)) */
sc_err_t cn_transfer_compute_id(uint8_t source_chain, const uint8_t source_tx_hash[32],
                                 uint8_t transfer_id_out[32]);

/* Calculate destination amount using rational arithmetic (overflow-safe) */
sc_err_t cn_transfer_calc_dest_amount(uint64_t source_amount, 
                                       uint64_t rate_num, uint64_t rate_den,
                                       uint64_t *dest_amount_out);

/* Create a transfer record from an observed cross-chain tx */
sc_err_t cn_transfer_create(cn_transfer_t *xfr, uint8_t source_chain,
                             const sc_tx_t *source_tx,
                             const cn_rate_t *applicable_rate);

/* Sign a vote on a transfer (domain: "XFER_VOTE/v1" || transfer_id || dest_amount || rate_version) */
sc_err_t cn_transfer_sign_vote(const cn_transfer_t *xfr, const sc_keypair_t *my_kp,
                                uint8_t sig_out[SC_ED25519_SIG_LEN]);

/* Verify a vote signature */
sc_err_t cn_transfer_verify_vote(const cn_transfer_t *xfr,
                                  const uint8_t voter_pubkey[32],
                                  const uint8_t sig[64]);

/* Add a vote to the transfer record, returns true if quorum reached */
bool cn_transfer_add_vote(cn_transfer_t *xfr, const uint8_t voter_pubkey[32],
                           const uint8_t sig[64], int quorum);

/* State transition helpers */
sc_err_t cn_transfer_transition(cn_transfer_t *xfr, cn_transfer_state_t new_state,
                                 const char *detail);

/* Wire serialization of transfer core fields */
sc_err_t cn_transfer_serialize(const cn_transfer_t *xfr, uint8_t *buf, size_t buflen, size_t *written);
sc_err_t cn_transfer_deserialize(cn_transfer_t *xfr, const uint8_t *buf, size_t len);

#endif /* CN_TRANSFER_H */
