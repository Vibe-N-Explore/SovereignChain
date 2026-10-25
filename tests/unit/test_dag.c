/* test_dag.c - unit tests for DAG vertex creation, hashing, serialization, and storage. */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto.h"
#include "dag.h"
#include "err.h"
#include "log.h"
#include "testutil.h"
#include "tx.h"

static void test_vertex_create_and_verify(void)
{
    sc_keypair_t *validator0_kp = NULL;
    CHECK(crypto_keygen(&validator0_kp) == SC_OK);

    sc_keypair_t *alice = NULL;
    sc_keypair_t *bob = NULL;
    CHECK(crypto_keygen(&alice) == SC_OK);
    CHECK(crypto_keygen(&bob) == SC_OK);

    uint8_t bob_pub[SC_ED25519_PUBKEY_LEN];
    CHECK(crypto_get_pubkey(bob, bob_pub) == SC_OK);

    sc_tx_t tx1;
    CHECK(tx_create(&tx1, alice, bob_pub, 100, 1, 0) == SC_OK);

    sc_vertex_t v;
    CHECK(vertex_create(&v, 1, 0, validator0_kp, NULL, 0, &tx1, 1) == SC_OK);
    CHECK(v.round == 1);
    CHECK(v.author == 0);
    CHECK(v.tx_count == 1);
    CHECK(v.parent_count == 0);

    /* Verify signature */
    CHECK(vertex_verify_sig(&v) == SC_OK);

    /* Tamper with tx_batch_hash */
    v.tx_batch_hash[0] ^= 0xFF;
    CHECK(vertex_verify_sig(&v) == SC_ERR_INVALID);

    crypto_keypair_free(validator0_kp);
    crypto_keypair_free(alice);
    crypto_keypair_free(bob);
}

static void test_vertex_serialization_roundtrip(void)
{
    sc_keypair_t *val_kp = NULL;
    sc_keypair_t *user_kp = NULL;
    CHECK(crypto_keygen(&val_kp) == SC_OK);
    CHECK(crypto_keygen(&user_kp) == SC_OK);

    uint8_t user_pub[SC_ED25519_PUBKEY_LEN];
    CHECK(crypto_get_pubkey(user_kp, user_pub) == SC_OK);

    sc_tx_t txs[2];
    CHECK(tx_create(&txs[0], user_kp, user_pub, 200, 5, 0) == SC_OK);
    CHECK(tx_create(&txs[1], user_kp, user_pub, 300, 10, 1) == SC_OK);

    uint8_t dummy_parent[SC_SHA256_LEN] = {0xAA};
    const uint8_t parents[1][SC_SHA256_LEN] = { {0xAA} };

    sc_vertex_t v1;
    CHECK(vertex_create(&v1, 2, 1, val_kp, parents, 1, txs, 2) == SC_OK);

    uint8_t wire[4096];
    size_t written = 0;
    CHECK(vertex_serialize(&v1, wire, sizeof(wire), &written) == SC_OK);
    CHECK(written > 0);

    sc_vertex_t v2;
    CHECK(vertex_deserialize(&v2, wire, written) == SC_OK);

    CHECK(v2.round == 2);
    CHECK(v2.author == 1);
    CHECK(v2.parent_count == 1);
    CHECK(memcmp(v2.parent_hashes[0], dummy_parent, SC_SHA256_LEN) == 0);
    CHECK(v2.tx_count == 2);
    CHECK(memcmp(v1.vertex_hash, v2.vertex_hash, SC_SHA256_LEN) == 0);
    CHECK(memcmp(v1.signature, v2.signature, SC_ED25519_SIG_LEN) == 0);

    CHECK(vertex_verify_sig(&v2) == SC_OK);

    crypto_keypair_free(val_kp);
    crypto_keypair_free(user_kp);
}

static void test_dag_storage_and_causal_history(void)
{
    sc_dag_t *dag = NULL;
    CHECK(dag_create(&dag) == SC_OK);
    CHECK(dag_vertex_count(dag) == 0);

    sc_keypair_t *v0_kp = NULL;
    sc_keypair_t *v1_kp = NULL;
    CHECK(crypto_keygen(&v0_kp) == SC_OK);
    CHECK(crypto_keygen(&v1_kp) == SC_OK);

    /* Round 1: v0_r1 and v1_r1 */
    sc_vertex_t v0_r1, v1_r1;
    CHECK(vertex_create(&v0_r1, 1, 0, v0_kp, NULL, 0, NULL, 0) == SC_OK);
    CHECK(vertex_create(&v1_r1, 1, 1, v1_kp, NULL, 0, NULL, 0) == SC_OK);
    CHECK(dag_add_vertex(dag, &v0_r1) == SC_OK);
    CHECK(dag_add_vertex(dag, &v1_r1) == SC_OK);
    CHECK(dag_vertex_count(dag) == 2);

    /* Round 2: v0_r2 points to v0_r1 and v1_r1 */
    uint8_t r1_parents[2][SC_SHA256_LEN];
    memcpy(r1_parents[0], v0_r1.vertex_hash, SC_SHA256_LEN);
    memcpy(r1_parents[1], v1_r1.vertex_hash, SC_SHA256_LEN);

    sc_vertex_t v0_r2;
    CHECK(vertex_create(&v0_r2, 2, 0, v0_kp, (const uint8_t (*)[32])r1_parents, 2, NULL, 0) == SC_OK);
    CHECK(dag_add_vertex(dag, &v0_r2) == SC_OK);
    CHECK(dag_vertex_count(dag) == 3);

    /* Lookup */
    CHECK(dag_has_vertex(dag, v0_r2.vertex_hash) == true);
    const sc_vertex_t *found = dag_get_by_round_author(dag, 2, 0);
    CHECK(found != NULL);
    CHECK(memcmp(found->vertex_hash, v0_r2.vertex_hash, SC_SHA256_LEN) == 0);

    /* Causal history of v0_r2 must contain v0_r1, v1_r1, and v0_r2 */
    const sc_vertex_t *history[10];
    size_t count = 0;
    CHECK(dag_get_causal_history(dag, v0_r2.vertex_hash, history, 10, &count) == SC_OK);
    CHECK(count == 3);

    dag_free(dag);
    crypto_keypair_free(v0_kp);
    crypto_keypair_free(v1_kp);
}

int main(void)
{
    log_init(-1);
    printf("test_dag\n");
    RUN(test_vertex_create_and_verify);
    RUN(test_vertex_serialization_roundtrip);
    RUN(test_dag_storage_and_causal_history);
    return TEST_SUMMARY();
}
