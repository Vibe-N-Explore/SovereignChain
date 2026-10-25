/* cn_store.h - Persistent storage for activity records, transfers, and seen IDs. */
#ifndef CN_STORE_H
#define CN_STORE_H

#include "connector_types.h"

typedef struct cn_store cn_store_t;

/* Open/create persistent store in data_dir */
sc_err_t cn_store_open(cn_store_t **store_out, const char *data_dir);

/* Close store and free resources */
void cn_store_close(cn_store_t *store);

/* Activity records */
sc_err_t cn_store_has_activity(cn_store_t *store, const uint8_t record_id[32], bool *out);
sc_err_t cn_store_add_activity(cn_store_t *store, const cn_activity_record_t *rec);
sc_err_t cn_store_get_activity_since(cn_store_t *store, uint64_t since_seq, 
                                      cn_activity_record_t *out, size_t max, size_t *count_out);
uint64_t cn_store_activity_count(cn_store_t *store);
sc_err_t cn_store_get_activity_by_id(cn_store_t *store, const uint8_t record_id[32],
                                      cn_activity_record_t *out);

/* Transfers */
sc_err_t cn_store_has_transfer(cn_store_t *store, const uint8_t transfer_id[32], bool *out);
sc_err_t cn_store_upsert_transfer(cn_store_t *store, const cn_transfer_t *xfr);
sc_err_t cn_store_get_transfer(cn_store_t *store, const uint8_t transfer_id[32],
                                cn_transfer_t *out);
sc_err_t cn_store_get_transfers_by_state(cn_store_t *store, cn_transfer_state_t state,
                                          cn_transfer_t *out, size_t max, size_t *count_out);

/* Read-only indexed access (used by the HTTP API). Index 0 is the oldest transfer. */
size_t cn_store_transfer_count(cn_store_t *store);
sc_err_t cn_store_get_transfer_at(cn_store_t *store, size_t index, cn_transfer_t *out);

/* Seen cert IDs (for deduplication) */
sc_err_t cn_store_mark_seen(cn_store_t *store, const uint8_t id[32]);
sc_err_t cn_store_is_seen(cn_store_t *store, const uint8_t id[32], bool *out);

#endif /* CN_STORE_H */
