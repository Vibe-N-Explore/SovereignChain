/* test_cn_activity.c - Unit tests for activity record creation, signing, and verification. */
#define _POSIX_C_SOURCE 200809L

#include "testutil.h"
#include "cn_activity.h"
#include "connector_types.h"
#include "../../src/crypto.h"

#include <string.h>

static void test_activity_compute_id(void)
{
    uint8_t tx_hash[32];
    memset(tx_hash, 0xAA, 32);

    uint8_t id1[32], id2[32], id3[32];
    CHECK(cn_activity_compute_id(CN_CHAIN_A, tx_hash, id1) == SC_OK);
    CHECK(cn_activity_compute_id(CN_CHAIN_A, tx_hash, id2) == SC_OK);
    CHECK(cn_activity_compute_id(CN_CHAIN_B, tx_hash, id3) == SC_OK);

    /* Deterministic: same chain + tx_hash -> same record_id */
    CHECK(memcmp(id1, id2, 32) == 0);

    /* Different chain -> different record_id */
    CHECK(memcmp(id1, id3, 32) != 0);
}

static void test_activity_create_and_verify(void)
{
    sc_keypair_t *reporter_kp = NULL;
    CHECK(crypto_keygen(&reporter_kp) == SC_OK);

    sc_tx_t tx;
    memset(&tx, 0, sizeof(tx));
    memset(tx.hash, 0x12, 32);
    memset(tx.sender, 0x34, 32);
    memset(tx.recipient, 0x56, 32);
    tx.amount = 50000;
    tx.fee = 100;
    tx.nonce = 10;

    uint8_t vertex_hash[32];
    memset(vertex_hash, 0x78, 32);

    cn_activity_record_t rec;
    CHECK(cn_activity_create(&rec, CN_CHAIN_A, &tx, 42, vertex_hash,
                             CN_STATUS_FINALIZED, reporter_kp) == SC_OK);

    CHECK(rec.source_chain == CN_CHAIN_A);
    CHECK(rec.amount == 50000);
    CHECK(rec.source_round == 42);
    CHECK(rec.status == CN_STATUS_FINALIZED);

    /* Verification should succeed */
    CHECK(cn_activity_verify(&rec) == SC_OK);

    /* Tamper status -> verification must fail */
    rec.status = CN_STATUS_REJECTED;
    CHECK(cn_activity_verify(&rec) != SC_OK);
    rec.status = CN_STATUS_FINALIZED;

    /* Tamper observed_at -> verification must fail */
    rec.observed_at += 1;
    CHECK(cn_activity_verify(&rec) != SC_OK);
    rec.observed_at -= 1;

    /* Tamper tx_hash -> verification must fail */
    rec.tx_hash[0] ^= 0xFF;
    CHECK(cn_activity_verify(&rec) != SC_OK);
    rec.tx_hash[0] ^= 0xFF;

    /* Tamper record_id -> verification must fail */
    rec.record_id[0] ^= 0xFF;
    CHECK(cn_activity_verify(&rec) != SC_OK);
    rec.record_id[0] ^= 0xFF;

    /* After undoing all tampers, verify succeeds again */
    CHECK(cn_activity_verify(&rec) == SC_OK);

    crypto_keypair_free(reporter_kp);
}

int main(void)
{
    printf("test_cn_activity:\n");
    RUN(test_activity_compute_id);
    RUN(test_activity_create_and_verify);
    return TEST_SUMMARY();
}
