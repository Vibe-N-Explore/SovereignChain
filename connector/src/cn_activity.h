/* cn_activity.h - Activity record creation, serialization, verification. */
#ifndef CN_ACTIVITY_H
#define CN_ACTIVITY_H

#include "connector_types.h"

/* Compute record_id: SHA-256("ACTIVITY/v1" || source_chain || tx_hash) */
sc_err_t cn_activity_compute_id(uint8_t source_chain, const uint8_t tx_hash[32],
                                 uint8_t record_id_out[32]);

/* Create and sign an activity record from a transaction observed on chain_id */
sc_err_t cn_activity_create(cn_activity_record_t *rec, uint8_t source_chain,
                             const sc_tx_t *tx, uint64_t source_round,
                             const uint8_t source_vertex_hash[32],
                             cn_activity_status_t status,
                             const sc_keypair_t *my_kp);

/* Verify reporter signature and record_id on an activity record */
sc_err_t cn_activity_verify(const cn_activity_record_t *rec);

/* Serialize/deserialize for wire transmission */
sc_err_t cn_activity_serialize(const cn_activity_record_t *rec, uint8_t *buf, size_t buflen, size_t *written);
sc_err_t cn_activity_deserialize(cn_activity_record_t *rec, const uint8_t *buf, size_t len);

#endif /* CN_ACTIVITY_H */
