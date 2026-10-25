/* mempool.h - Memory pool for pending transactions.
 *
 * Phase 4: Transactions, Mempool, and Transaction Gossip.
 *
 * The mempool serves as each node's staging area for uncommitted transactions:
 *   - Deduplication by 32-byte transaction hash
 *   - Signature verification and sanity checks prior to admission
 *   - Bounded capacity to prevent memory-exhaustion DoS
 *   - Extraction of batches for DAG vertex creation
 *   - Atomic removal of transactions once committed by consensus
 */
#ifndef SC_MEMPOOL_H
#define SC_MEMPOOL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "crypto.h"
#include "err.h"
#include "tx.h"

#define SC_MEMPOOL_CAPACITY 1024

typedef struct sc_mempool sc_mempool_t;

/* Create a new empty mempool */
sc_err_t mempool_create(sc_mempool_t **pool_out);

/* Free all memory associated with the mempool */
void mempool_free(sc_mempool_t *pool);

/* Check if transaction with given 32-byte hash is currently in the pool */
bool mempool_has(const sc_mempool_t *pool, const uint8_t hash[SC_SHA256_LEN]);

/* Validate and add a transaction to the pool.
 * Returns SC_OK if added, or if it was already present (duplicate).
 * Sets *added_out to true if freshly inserted, false if duplicate. */
sc_err_t mempool_add(sc_mempool_t *pool, const sc_tx_t *tx, bool *added_out);

/* Fetch up to max_count transactions from the pool into txs_out.
 * Transactions remain in the pool until explicitly removed. */
sc_err_t mempool_get_batch(const sc_mempool_t *pool, size_t max_count,
                           sc_tx_t *txs_out, size_t *count_out);

/* Remove a transaction by hash (e.g. after it has been executed in consensus) */
sc_err_t mempool_remove(sc_mempool_t *pool, const uint8_t hash[SC_SHA256_LEN]);

/* Remove a batch of transactions by their hashes */
void mempool_remove_batch(sc_mempool_t *pool,
                          const uint8_t hashes[][SC_SHA256_LEN],
                          size_t count);

/* Return number of transactions currently in pool */
size_t mempool_count(const sc_mempool_t *pool);

/* Clear all transactions from pool */
void mempool_clear(sc_mempool_t *pool);

#endif /* SC_MEMPOOL_H */
