/* test_consensus.c - unit tests for SPD 2-of-2 consensus, anchors, ordering, and equivocation. */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "consensus.h"
#include "crypto.h"
#include "dag.h"
#include "err.h"
#include "ledger.h"
#include "log.h"
#include "mempool.h"
#include "testutil.h"
#include "tx.h"

static void setup_test_topology(network_config_t *net, sc_keypair_t **kps)
{
    memset(net, 0, sizeof(*net));
    net->count = 6;
    for (int i = 0; i < 6; i++) {
        CHECK(crypto_keygen(&kps[i]) == SC_OK);
        net->nodes[i].id = i;
        net->nodes[i].role = (i < 2) ? ROLE_VALIDATOR : ROLE_NORMAL;
        snprintf(net->nodes[i].host, sizeof(net->nodes[i].host), "127.0.0.1");
        net->nodes[i].port = 9000 + i;
        CHECK(crypto_get_pubkey(kps[i], net->nodes[i].pubkey) == SC_OK);
        net->nodes[i].has_pubkey = true;
    }
}

static void test_consensus_voting_and_certification(void)
{
    network_config_t net;
    sc_keypair_t *kps[6];
    setup_test_topology(&net, kps);

    sc_dag_t *dag = NULL;
    CHECK(dag_create(&dag) == SC_OK);

    sc_consensus_t *cons0 = NULL;
    CHECK(consensus_create(&cons0, &net, 0, kps[0], dag, NULL, NULL, NULL) == SC_OK);

    /* Validator 0 proposes round 1 vertex */
    sc_vertex_t v0;
    CHECK(vertex_create(&v0, 1, 0, kps[0], NULL, 0, NULL, 0) == SC_OK);
    CHECK(dag_add_vertex(dag, &v0) == SC_OK);

    /* Validator 0 votes on v0 */
    uint8_t sig0[SC_ED25519_SIG_LEN];
    CHECK(consensus_vote_vertex(cons0, &v0, sig0) == SC_OK);

    bool certified = false;
    CHECK(consensus_add_vote(cons0, v0.vertex_hash, 0, sig0, &certified) == SC_OK);
    CHECK(certified == false); /* Only 1 of 2 votes */

    /* Validator 1 votes on v0 */
    sc_consensus_t *cons1 = NULL;
    CHECK(consensus_create(&cons1, &net, 1, kps[1], dag, NULL, NULL, NULL) == SC_OK);
    uint8_t sig1[SC_ED25519_SIG_LEN];
    CHECK(consensus_vote_vertex(cons1, &v0, sig1) == SC_OK);

    CHECK(consensus_add_vote(cons0, v0.vertex_hash, 1, sig1, &certified) == SC_OK);
    CHECK(certified == true); /* 2 of 2 quorum reached! */
    CHECK(consensus_is_certified(cons0, v0.vertex_hash) == true);

    /* Normal node (Node 2) can verify the complete certificate */
    const sc_certificate_t *cert = consensus_get_certificate(cons0, v0.vertex_hash);
    CHECK(cert != NULL);
    sc_consensus_t *cons2 = NULL;
    CHECK(consensus_create(&cons2, &net, 2, kps[2], dag, NULL, NULL, NULL) == SC_OK);
    CHECK(consensus_add_certificate(cons2, cert) == SC_OK);
    CHECK(consensus_is_certified(cons2, v0.vertex_hash) == true);

    consensus_free(cons0);
    consensus_free(cons1);
    consensus_free(cons2);
    dag_free(dag);
    for (int i = 0; i < 6; i++) {
        crypto_keypair_free(kps[i]);
    }
}

static void test_equivocation_detection(void)
{
    network_config_t net;
    sc_keypair_t *kps[6];
    setup_test_topology(&net, kps);

    sc_dag_t *dag = NULL;
    CHECK(dag_create(&dag) == SC_OK);

    sc_consensus_t *cons = NULL;
    CHECK(consensus_create(&cons, &net, 1, kps[1], dag, NULL, NULL, NULL) == SC_OK);

    /* Malicious Validator 0 creates two DIFFERENT vertices for round 1 */
    sc_keypair_t *user_kp = NULL;
    CHECK(crypto_keygen(&user_kp) == SC_OK);
    uint8_t user_pub[SC_ED25519_PUBKEY_LEN];
    CHECK(crypto_get_pubkey(user_kp, user_pub) == SC_OK);

    sc_tx_t tx_a, tx_b;
    CHECK(tx_create(&tx_a, user_kp, user_pub, 100, 1, 0) == SC_OK);
    CHECK(tx_create(&tx_b, user_kp, user_pub, 200, 2, 0) == SC_OK);

    sc_vertex_t va, vb;
    CHECK(vertex_create(&va, 1, 0, kps[0], NULL, 0, &tx_a, 1) == SC_OK);
    CHECK(vertex_create(&vb, 1, 0, kps[0], NULL, 0, &tx_b, 1) == SC_OK);

    CHECK(dag_add_vertex(dag, &va) == SC_OK);

    /* Validator 1 votes on va */
    uint8_t sig[SC_ED25519_SIG_LEN];
    CHECK(consensus_vote_vertex(cons, &va, sig) == SC_OK);
    CHECK(consensus_has_equivocation(cons) == false);

    /* Attacker presents conflicting vertex vb for the same round 1 from author 0 */
    sc_err_t rc = consensus_vote_vertex(cons, &vb, sig);
    CHECK(rc == SC_ERR_INVALID);
    CHECK(consensus_has_equivocation(cons) == true);
    CHECK(consensus_equivocation_count(cons) == 1);

    consensus_free(cons);
    dag_free(dag);
    crypto_keypair_free(user_kp);
    for (int i = 0; i < 6; i++) {
        crypto_keypair_free(kps[i]);
    }
}

static void test_anchor_commit_and_deterministic_ordering(void)
{
    network_config_t net;
    sc_keypair_t *kps[6];
    setup_test_topology(&net, kps);

    sc_dag_t *dag0 = NULL;
    sc_dag_t *dag1 = NULL;
    CHECK(dag_create(&dag0) == SC_OK);
    CHECK(dag_create(&dag1) == SC_OK);

    sc_ledger_t *ledger0 = NULL;
    sc_ledger_t *ledger1 = NULL;
    CHECK(ledger_create(&ledger0) == SC_OK);
    CHECK(ledger_create(&ledger1) == SC_OK);

    /* Genesis state: fund Alice with 10,000 tokens */
    sc_keypair_t *alice = NULL;
    sc_keypair_t *bob = NULL;
    CHECK(crypto_keygen(&alice) == SC_OK);
    CHECK(crypto_keygen(&bob) == SC_OK);
    uint8_t alice_pub[SC_ED25519_PUBKEY_LEN];
    uint8_t bob_pub[SC_ED25519_PUBKEY_LEN];
    CHECK(crypto_get_pubkey(alice, alice_pub) == SC_OK);
    CHECK(crypto_get_pubkey(bob, bob_pub) == SC_OK);

    CHECK(ledger_set_account(ledger0, alice_pub, 10000, 0) == SC_OK);
    CHECK(ledger_set_account(ledger1, alice_pub, 10000, 0) == SC_OK);

    sc_mempool_t *mp0 = NULL;
    sc_mempool_t *mp1 = NULL;
    CHECK(mempool_create(&mp0) == SC_OK);
    CHECK(mempool_create(&mp1) == SC_OK);

    sc_consensus_t *cons0 = NULL;
    sc_consensus_t *cons1 = NULL;
    CHECK(consensus_create(&cons0, &net, 0, kps[0], dag0, ledger0, mp0, NULL) == SC_OK);
    CHECK(consensus_create(&cons1, &net, 1, kps[1], dag1, ledger1, mp1, NULL) == SC_OK);

    /* Create transactions */
    sc_tx_t tx1, tx2;
    CHECK(tx_create(&tx1, alice, bob_pub, 1000, 50, 0) == SC_OK);
    CHECK(tx_create(&tx2, alice, bob_pub, 2000, 50, 1) == SC_OK);

    /* Round 1 Anchor: Validator 0 proposes vertex v0_r1 with tx1 */
    sc_vertex_t v0_r1;
    CHECK(vertex_create(&v0_r1, 1, 0, kps[0], NULL, 0, &tx1, 1) == SC_OK);
    CHECK(dag_add_vertex(dag0, &v0_r1) == SC_OK);
    CHECK(dag_add_vertex(dag1, &v0_r1) == SC_OK);

    /* Certify v0_r1 on both nodes */
    uint8_t sig0[SC_ED25519_SIG_LEN], sig1[SC_ED25519_SIG_LEN];
    CHECK(consensus_vote_vertex(cons0, &v0_r1, sig0) == SC_OK);
    CHECK(consensus_vote_vertex(cons1, &v0_r1, sig1) == SC_OK);
    bool cert_ok = false;
    CHECK(consensus_add_vote(cons0, v0_r1.vertex_hash, 0, sig0, &cert_ok) == SC_OK);
    CHECK(consensus_add_vote(cons0, v0_r1.vertex_hash, 1, sig1, &cert_ok) == SC_OK);
    CHECK(cert_ok == true);

    const sc_certificate_t *cert_v0_r1 = consensus_get_certificate(cons0, v0_r1.vertex_hash);
    CHECK(consensus_add_certificate(cons1, cert_v0_r1) == SC_OK);

    /* Round 1 not yet committed because no Round 2 vertex references it */
    size_t comm = 0;
    CHECK(consensus_evaluate_commits(cons0, &comm) == SC_OK);
    CHECK(comm == 0);

    /* Round 2: Validator 1 proposes vertex v1_r2 referencing v0_r1 as parent with tx2 */
    const uint8_t r1_parents[1][SC_SHA256_LEN] = { {0} };
    memcpy((void *)r1_parents[0], v0_r1.vertex_hash, SC_SHA256_LEN);

    sc_vertex_t v1_r2;
    CHECK(vertex_create(&v1_r2, 2, 1, kps[1], r1_parents, 1, &tx2, 1) == SC_OK);
    CHECK(dag_add_vertex(dag0, &v1_r2) == SC_OK);
    CHECK(dag_add_vertex(dag1, &v1_r2) == SC_OK);

    /* Certify v1_r2 on both nodes */
    CHECK(consensus_vote_vertex(cons0, &v1_r2, sig0) == SC_OK);
    CHECK(consensus_vote_vertex(cons1, &v1_r2, sig1) == SC_OK);
    CHECK(consensus_add_vote(cons0, v1_r2.vertex_hash, 0, sig0, &cert_ok) == SC_OK);
    CHECK(consensus_add_vote(cons0, v1_r2.vertex_hash, 1, sig1, &cert_ok) == SC_OK);
    CHECK(cert_ok == true);

    const sc_certificate_t *cert_v1_r2 = consensus_get_certificate(cons0, v1_r2.vertex_hash);
    CHECK(consensus_add_certificate(cons1, cert_v1_r2) == SC_OK);

    /* Now evaluate commits on Node 0 and Node 1: Round 1 Anchor MUST COMMIT! */
    CHECK(consensus_evaluate_commits(cons0, &comm) == SC_OK);
    CHECK(comm == 1);
    CHECK(consensus_latest_committed_round(cons0) == 1);

    CHECK(consensus_evaluate_commits(cons1, &comm) == SC_OK);
    CHECK(comm == 1);
    CHECK(consensus_latest_committed_round(cons1) == 1);

    /* State hash MUST be 100% IDENTICAL across Node 0 and Node 1 */
    uint8_t hash0[SC_SHA256_LEN], hash1[SC_SHA256_LEN];
    CHECK(ledger_compute_state_hash(ledger0, hash0) == SC_OK);
    CHECK(ledger_compute_state_hash(ledger1, hash1) == SC_OK);
    CHECK(memcmp(hash0, hash1, SC_SHA256_LEN) == 0);

    /* Verify Alice's balance was deducted and Bob was credited */
    sc_account_t acc_alice, acc_bob;
    CHECK(ledger_get_account(ledger0, alice_pub, &acc_alice) == SC_OK);
    CHECK(acc_alice.balance == 10000 - 1050); /* 8950 */
    CHECK(acc_alice.nonce == 1);

    CHECK(ledger_get_account(ledger0, bob_pub, &acc_bob) == SC_OK);
    CHECK(acc_bob.balance == 1000);

    consensus_free(cons0);
    consensus_free(cons1);
    ledger_free(ledger0);
    ledger_free(ledger1);
    mempool_free(mp0);
    mempool_free(mp1);
    dag_free(dag0);
    dag_free(dag1);
    crypto_keypair_free(alice);
    crypto_keypair_free(bob);
    for (int i = 0; i < 6; i++) {
        crypto_keypair_free(kps[i]);
    }
}

int main(void)
{
    log_init(-1);
    printf("test_consensus\n");
    RUN(test_consensus_voting_and_certification);
    RUN(test_equivocation_detection);
    RUN(test_anchor_commit_and_deterministic_ordering);
    return TEST_SUMMARY();
}
