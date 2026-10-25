/* mempool.c - Memory pool implementation for pending transactions. */
#define _POSIX_C_SOURCE 200809L

#include "mempool.h"

#include <stdlib.h>
#include <string.h>

#include "log.h"

struct sc_mempool {
    sc_tx_t entries[SC_MEMPOOL_CAPACITY];
    bool    occupied[SC_MEMPOOL_CAPACITY];
    size_t  count;
};

sc_err_t mempool_create(sc_mempool_t **pool_out)
{
    if (!pool_out)
        return SC_ERR_INVALID;

    sc_mempool_t *p = calloc(1, sizeof(*p));
    if (!p)
        return SC_ERR_IO;

    *pool_out = p;
    return SC_OK;
}

void mempool_free(sc_mempool_t *pool)
{
    free(pool);
}

bool mempool_has(const sc_mempool_t *pool, const uint8_t hash[SC_SHA256_LEN])
{
    if (!pool || !hash)
        return false;

    for (size_t i = 0; i < SC_MEMPOOL_CAPACITY; i++) {
        if (pool->occupied[i] && memcmp(pool->entries[i].hash, hash, SC_SHA256_LEN) == 0) {
            return true;
        }
    }
    return false;
}

sc_err_t mempool_add(sc_mempool_t *pool, const sc_tx_t *tx, bool *added_out)
{
    if (added_out)
        *added_out = false;

    if (!pool || !tx)
        return SC_ERR_INVALID;

    /* 1. Deduplication check */
    if (mempool_has(pool, tx->hash)) {
        return SC_OK; /* Already present, not an error */
    }

    /* 2. Sanity check transaction fields */
    if (tx->amount == 0) {
        return SC_ERR_INVALID;
    }

    /* 3. Cryptographic signature check */
    if (tx_verify_sig(tx) != SC_OK) {
        return SC_ERR_INVALID;
    }

    /* 4. Check capacity */
    if (pool->count >= SC_MEMPOOL_CAPACITY) {
        return SC_ERR_INVALID; /* Pool full */
    }

    /* 5. Insert into first free slot */
    for (size_t i = 0; i < SC_MEMPOOL_CAPACITY; i++) {
        if (!pool->occupied[i]) {
            pool->entries[i] = *tx;
            pool->occupied[i] = true;
            pool->count++;
            if (added_out)
                *added_out = true;
            return SC_OK;
        }
    }

    return SC_ERR_INVALID;
}

sc_err_t mempool_get_batch(const sc_mempool_t *pool, size_t max_count,
                           sc_tx_t *txs_out, size_t *count_out)
{
    if (!pool || !count_out)
        return SC_ERR_INVALID;

    size_t fetched = 0;
    for (size_t i = 0; i < SC_MEMPOOL_CAPACITY && fetched < max_count; i++) {
        if (pool->occupied[i]) {
            if (txs_out) {
                txs_out[fetched] = pool->entries[i];
            }
            fetched++;
        }
    }

    *count_out = fetched;
    return SC_OK;
}

sc_err_t mempool_remove(sc_mempool_t *pool, const uint8_t hash[SC_SHA256_LEN])
{
    if (!pool || !hash)
        return SC_ERR_INVALID;

    for (size_t i = 0; i < SC_MEMPOOL_CAPACITY; i++) {
        if (pool->occupied[i] && memcmp(pool->entries[i].hash, hash, SC_SHA256_LEN) == 0) {
            pool->occupied[i] = false;
            pool->count--;
            return SC_OK;
        }
    }

    return SC_ERR_NOT_FOUND;
}

void mempool_remove_batch(sc_mempool_t *pool,
                          const uint8_t hashes[][SC_SHA256_LEN],
                          size_t count)
{
    if (!pool || !hashes)
        return;

    for (size_t i = 0; i < count; i++) {
        mempool_remove(pool, hashes[i]);
    }
}

size_t mempool_count(const sc_mempool_t *pool)
{
    return pool ? pool->count : 0;
}

void mempool_clear(sc_mempool_t *pool)
{
    if (!pool)
        return;
    memset(pool, 0, sizeof(*pool));
}
