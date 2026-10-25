/* test_mempool.c - unit tests for transaction mempool, validation, and deduplication. */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto.h"
#include "err.h"
#include "log.h"
#include "mempool.h"
#include "testutil.h"
#include "tx.h"

static void test_mempool_basic(void)
{
    sc_mempool_t *pool = NULL;
    CHECK(mempool_create(&pool) == SC_OK);
    CHECK(mempool_count(pool) == 0);

    sc_keypair_t *alice = NULL;
    sc_keypair_t *bob = NULL;
    CHECK(crypto_keygen(&alice) == SC_OK);
    CHECK(crypto_keygen(&bob) == SC_OK);

    uint8_t bob_pub[SC_ED25519_PUBKEY_LEN];
    CHECK(crypto_get_pubkey(bob, bob_pub) == SC_OK);

    sc_tx_t tx1;
    CHECK(tx_create(&tx1, alice, bob_pub, 500, 10, 0) == SC_OK);

    bool added = false;
    CHECK(mempool_add(pool, &tx1, &added) == SC_OK);
    CHECK(added == true);
    CHECK(mempool_count(pool) == 1);
    CHECK(mempool_has(pool, tx1.hash) == true);

    /* Duplicate addition */
    added = true;
    CHECK(mempool_add(pool, &tx1, &added) == SC_OK);
    CHECK(added == false);
    CHECK(mempool_count(pool) == 1);

    /* Second transaction */
    sc_tx_t tx2;
    CHECK(tx_create(&tx2, alice, bob_pub, 250, 5, 1) == SC_OK);
    CHECK(mempool_add(pool, &tx2, &added) == SC_OK);
    CHECK(added == true);
    CHECK(mempool_count(pool) == 2);

    /* Fetch batch */
    sc_tx_t batch[4];
    size_t count = 0;
    CHECK(mempool_get_batch(pool, 4, batch, &count) == SC_OK);
    CHECK(count == 2);

    /* Removal */
    CHECK(mempool_remove(pool, tx1.hash) == SC_OK);
    CHECK(mempool_count(pool) == 1);
    CHECK(mempool_has(pool, tx1.hash) == false);
    CHECK(mempool_has(pool, tx2.hash) == true);

    mempool_free(pool);
    crypto_keypair_free(alice);
    crypto_keypair_free(bob);
}

static void test_mempool_invalid_tx_rejected(void)
{
    sc_mempool_t *pool = NULL;
    CHECK(mempool_create(&pool) == SC_OK);

    sc_keypair_t *alice = NULL;
    sc_keypair_t *bob = NULL;
    CHECK(crypto_keygen(&alice) == SC_OK);
    CHECK(crypto_keygen(&bob) == SC_OK);

    uint8_t bob_pub[SC_ED25519_PUBKEY_LEN];
    CHECK(crypto_get_pubkey(bob, bob_pub) == SC_OK);

    sc_tx_t tx;
    CHECK(tx_create(&tx, alice, bob_pub, 500, 10, 0) == SC_OK);

    /* Tamper with signature */
    tx.sig[0] ^= 0xFF;
    bool added = false;
    CHECK(mempool_add(pool, &tx, &added) == SC_ERR_INVALID);
    CHECK(added == false);
    CHECK(mempool_count(pool) == 0);

    /* Restore and set zero amount */
    CHECK(tx_create(&tx, alice, bob_pub, 0, 10, 0) == SC_OK);
    CHECK(mempool_add(pool, &tx, &added) == SC_ERR_INVALID);
    CHECK(mempool_count(pool) == 0);

    mempool_free(pool);
    crypto_keypair_free(alice);
    crypto_keypair_free(bob);
}

int main(void)
{
    log_init(-1);
    printf("test_mempool\n");
    RUN(test_mempool_basic);
    RUN(test_mempool_invalid_tx_rejected);
    return TEST_SUMMARY();
}
