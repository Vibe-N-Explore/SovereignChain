/* test_ledger.c - unit tests for account ledger, deterministic execution, and state hashing. */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto.h"
#include "err.h"
#include "ledger.h"
#include "log.h"
#include "testutil.h"
#include "tx.h"

static void test_genesis_and_lookup(void)
{
    sc_ledger_t *ledger = NULL;
    CHECK(ledger_create(&ledger) == SC_OK);
    CHECK(ledger_account_count(ledger) == 0);

    sc_keypair_t *kp_alice = NULL;
    sc_keypair_t *kp_bob = NULL;
    CHECK(crypto_keygen(&kp_alice) == SC_OK);
    CHECK(crypto_keygen(&kp_bob) == SC_OK);

    uint8_t pub_alice[SC_ED25519_PUBKEY_LEN];
    uint8_t pub_bob[SC_ED25519_PUBKEY_LEN];
    CHECK(crypto_get_pubkey(kp_alice, pub_alice) == SC_OK);
    CHECK(crypto_get_pubkey(kp_bob, pub_bob) == SC_OK);

    sc_genesis_account_t genesis[2] = {
        { .initial_balance = 5000000 },
        { .initial_balance = 2000000 }
    };
    memcpy(genesis[0].pubkey, pub_alice, SC_ED25519_PUBKEY_LEN);
    memcpy(genesis[1].pubkey, pub_bob, SC_ED25519_PUBKEY_LEN);

    CHECK(ledger_init_genesis(ledger, genesis, 2) == SC_OK);
    CHECK(ledger_account_count(ledger) == 2);

    sc_account_t acc;
    CHECK(ledger_get_account(ledger, pub_alice, &acc) == SC_OK);
    CHECK(acc.balance == 5000000);
    CHECK(acc.nonce == 0);

    CHECK(ledger_get_account(ledger, pub_bob, &acc) == SC_OK);
    CHECK(acc.balance == 2000000);
    CHECK(acc.nonce == 0);

    /* Non-existent account lookup */
    uint8_t unknown_pub[SC_ED25519_PUBKEY_LEN] = { 0xFF };
    CHECK(ledger_get_account(ledger, unknown_pub, &acc) == SC_ERR_NOT_FOUND);

    ledger_free(ledger);
    crypto_keypair_free(kp_alice);
    crypto_keypair_free(kp_bob);
}

static void test_valid_transfer_execution(void)
{
    sc_ledger_t *ledger = NULL;
    CHECK(ledger_create(&ledger) == SC_OK);

    sc_keypair_t *kp_alice = NULL;
    sc_keypair_t *kp_bob = NULL;
    CHECK(crypto_keygen(&kp_alice) == SC_OK);
    CHECK(crypto_keygen(&kp_bob) == SC_OK);

    uint8_t pub_alice[SC_ED25519_PUBKEY_LEN];
    uint8_t pub_bob[SC_ED25519_PUBKEY_LEN];
    CHECK(crypto_get_pubkey(kp_alice, pub_alice) == SC_OK);
    CHECK(crypto_get_pubkey(kp_bob, pub_bob) == SC_OK);

    /* Fund Alice with 10,000 tokens */
    CHECK(ledger_set_account(ledger, pub_alice, 10000, 0) == SC_OK);

    /* Alice sends 3,000 tokens to Bob (fee 100, nonce 0) */
    sc_tx_t tx;
    CHECK(tx_create(&tx, kp_alice, pub_bob, 3000, 100, 0) == SC_OK);

    char err[128];
    CHECK(ledger_apply_tx(ledger, &tx, err, sizeof(err)) == SC_OK);

    /* Alice should now have 10,000 - 3,100 = 6,900 tokens and nonce 1 */
    sc_account_t acc_alice;
    CHECK(ledger_get_account(ledger, pub_alice, &acc_alice) == SC_OK);
    CHECK(acc_alice.balance == 6900);
    CHECK(acc_alice.nonce == 1);

    /* Bob should have 3,000 tokens and nonce 0 */
    sc_account_t acc_bob;
    CHECK(ledger_get_account(ledger, pub_bob, &acc_bob) == SC_OK);
    CHECK(acc_bob.balance == 3000);
    CHECK(acc_bob.nonce == 0);

    /* Alice sends second transaction (nonce 1) */
    sc_tx_t tx2;
    CHECK(tx_create(&tx2, kp_alice, pub_bob, 1500, 50, 1) == SC_OK);
    CHECK(ledger_apply_tx(ledger, &tx2, err, sizeof(err)) == SC_OK);

    CHECK(ledger_get_account(ledger, pub_alice, &acc_alice) == SC_OK);
    CHECK(acc_alice.balance == 6900 - 1550);
    CHECK(acc_alice.nonce == 2);

    CHECK(ledger_get_account(ledger, pub_bob, &acc_bob) == SC_OK);
    CHECK(acc_bob.balance == 4500);

    ledger_free(ledger);
    crypto_keypair_free(kp_alice);
    crypto_keypair_free(kp_bob);
}

static void test_insufficient_balance_rejected(void)
{
    sc_ledger_t *ledger = NULL;
    CHECK(ledger_create(&ledger) == SC_OK);

    sc_keypair_t *kp_alice = NULL;
    sc_keypair_t *kp_bob = NULL;
    CHECK(crypto_keygen(&kp_alice) == SC_OK);
    CHECK(crypto_keygen(&kp_bob) == SC_OK);

    uint8_t pub_alice[SC_ED25519_PUBKEY_LEN];
    uint8_t pub_bob[SC_ED25519_PUBKEY_LEN];
    CHECK(crypto_get_pubkey(kp_alice, pub_alice) == SC_OK);
    CHECK(crypto_get_pubkey(kp_bob, pub_bob) == SC_OK);

    CHECK(ledger_set_account(ledger, pub_alice, 500, 0) == SC_OK);

    /* Alice tries to send 600 tokens (balance is only 500) */
    sc_tx_t tx;
    CHECK(tx_create(&tx, kp_alice, pub_bob, 600, 0, 0) == SC_OK);

    char err[128];
    CHECK(ledger_apply_tx(ledger, &tx, err, sizeof(err)) == SC_ERR_INVALID);
    CHECK_CONTAINS(err, "insufficient_balance");

    /* State must be completely unmodified */
    sc_account_t acc_alice;
    CHECK(ledger_get_account(ledger, pub_alice, &acc_alice) == SC_OK);
    CHECK(acc_alice.balance == 500);
    CHECK(acc_alice.nonce == 0);

    ledger_free(ledger);
    crypto_keypair_free(kp_alice);
    crypto_keypair_free(kp_bob);
}

static void test_nonce_ordering_enforced(void)
{
    sc_ledger_t *ledger = NULL;
    CHECK(ledger_create(&ledger) == SC_OK);

    sc_keypair_t *kp_alice = NULL;
    sc_keypair_t *kp_bob = NULL;
    CHECK(crypto_keygen(&kp_alice) == SC_OK);
    CHECK(crypto_keygen(&kp_bob) == SC_OK);

    uint8_t pub_alice[SC_ED25519_PUBKEY_LEN];
    uint8_t pub_bob[SC_ED25519_PUBKEY_LEN];
    CHECK(crypto_get_pubkey(kp_alice, pub_alice) == SC_OK);
    CHECK(crypto_get_pubkey(kp_bob, pub_bob) == SC_OK);

    CHECK(ledger_set_account(ledger, pub_alice, 5000, 1) == SC_OK);

    char err[128];

    /* Nonce too low (replay of nonce 0 when current is 1) */
    sc_tx_t tx_low;
    CHECK(tx_create(&tx_low, kp_alice, pub_bob, 100, 0, 0) == SC_OK);
    CHECK(ledger_apply_tx(ledger, &tx_low, err, sizeof(err)) == SC_ERR_INVALID);
    CHECK_CONTAINS(err, "nonce_too_low");

    /* Nonce too high (out of order nonce 5 when current is 1) */
    sc_tx_t tx_high;
    CHECK(tx_create(&tx_high, kp_alice, pub_bob, 100, 0, 5) == SC_OK);
    CHECK(ledger_apply_tx(ledger, &tx_high, err, sizeof(err)) == SC_ERR_INVALID);
    CHECK_CONTAINS(err, "nonce_too_high");

    /* Exactly matching nonce 1 succeeds */
    sc_tx_t tx_valid;
    CHECK(tx_create(&tx_valid, kp_alice, pub_bob, 100, 0, 1) == SC_OK);
    CHECK(ledger_apply_tx(ledger, &tx_valid, err, sizeof(err)) == SC_OK);

    sc_account_t acc_alice;
    CHECK(ledger_get_account(ledger, pub_alice, &acc_alice) == SC_OK);
    CHECK(acc_alice.nonce == 2);

    ledger_free(ledger);
    crypto_keypair_free(kp_alice);
    crypto_keypair_free(kp_bob);
}

static void test_forged_sig_rejected(void)
{
    sc_ledger_t *ledger = NULL;
    CHECK(ledger_create(&ledger) == SC_OK);

    sc_keypair_t *kp_alice = NULL;
    sc_keypair_t *kp_mallory = NULL;
    sc_keypair_t *kp_bob = NULL;
    CHECK(crypto_keygen(&kp_alice) == SC_OK);
    CHECK(crypto_keygen(&kp_mallory) == SC_OK);
    CHECK(crypto_keygen(&kp_bob) == SC_OK);

    uint8_t pub_alice[SC_ED25519_PUBKEY_LEN];
    uint8_t pub_bob[SC_ED25519_PUBKEY_LEN];
    CHECK(crypto_get_pubkey(kp_alice, pub_alice) == SC_OK);
    CHECK(crypto_get_pubkey(kp_bob, pub_bob) == SC_OK);

    CHECK(ledger_set_account(ledger, pub_alice, 5000, 0) == SC_OK);

    /* Mallory signs a transaction claiming to spend Alice's tokens */
    sc_tx_t tx;
    CHECK(tx_create(&tx, kp_mallory, pub_bob, 1000, 0, 0) == SC_OK);
    /* Mallory overwrites the sender field with Alice's pubkey */
    memcpy(tx.sender, pub_alice, SC_ED25519_PUBKEY_LEN);

    char err[128];
    CHECK(ledger_apply_tx(ledger, &tx, err, sizeof(err)) == SC_ERR_INVALID);
    CHECK_CONTAINS(err, "invalid_signature");

    ledger_free(ledger);
    crypto_keypair_free(kp_alice);
    crypto_keypair_free(kp_mallory);
    crypto_keypair_free(kp_bob);
}

static void test_self_transfer(void)
{
    sc_ledger_t *ledger = NULL;
    CHECK(ledger_create(&ledger) == SC_OK);

    sc_keypair_t *kp_alice = NULL;
    CHECK(crypto_keygen(&kp_alice) == SC_OK);

    uint8_t pub_alice[SC_ED25519_PUBKEY_LEN];
    CHECK(crypto_get_pubkey(kp_alice, pub_alice) == SC_OK);

    CHECK(ledger_set_account(ledger, pub_alice, 1000, 0) == SC_OK);

    /* Alice sends 500 to herself with fee 25 */
    sc_tx_t tx;
    CHECK(tx_create(&tx, kp_alice, pub_alice, 500, 25, 0) == SC_OK);

    char err[128];
    CHECK(ledger_apply_tx(ledger, &tx, err, sizeof(err)) == SC_OK);

    sc_account_t acc;
    CHECK(ledger_get_account(ledger, pub_alice, &acc) == SC_OK);
    CHECK(acc.balance == 975); /* 1000 - 25 fee */
    CHECK(acc.nonce == 1);

    ledger_free(ledger);
    crypto_keypair_free(kp_alice);
}

static void test_strict_batch_rollback(void)
{
    sc_ledger_t *ledger = NULL;
    CHECK(ledger_create(&ledger) == SC_OK);

    sc_keypair_t *kp_alice = NULL;
    sc_keypair_t *kp_bob = NULL;
    CHECK(crypto_keygen(&kp_alice) == SC_OK);
    CHECK(crypto_keygen(&kp_bob) == SC_OK);

    uint8_t pub_alice[SC_ED25519_PUBKEY_LEN];
    uint8_t pub_bob[SC_ED25519_PUBKEY_LEN];
    CHECK(crypto_get_pubkey(kp_alice, pub_alice) == SC_OK);
    CHECK(crypto_get_pubkey(kp_bob, pub_bob) == SC_OK);

    CHECK(ledger_set_account(ledger, pub_alice, 1000, 0) == SC_OK);

    sc_tx_t txs[3];
    /* Tx 0: Valid, spends 300, nonce 0 */
    CHECK(tx_create(&txs[0], kp_alice, pub_bob, 300, 0, 0) == SC_OK);
    /* Tx 1: Valid, spends 300, nonce 1 */
    CHECK(tx_create(&txs[1], kp_alice, pub_bob, 300, 0, 1) == SC_OK);
    /* Tx 2: Invalid, attempts to spend 500 (only 400 left!), nonce 2 */
    CHECK(tx_create(&txs[2], kp_alice, pub_bob, 500, 0, 2) == SC_OK);

    size_t applied = 0;
    /* Strict execution: must fail and rollback ALL transactions in the block */
    sc_err_t rc = ledger_apply_block(ledger, txs, 3, true, &applied);
    CHECK(rc == SC_ERR_INVALID);
    CHECK(applied == 0);

    /* State must be untouched: balance 1000, nonce 0 */
    sc_account_t acc_alice;
    CHECK(ledger_get_account(ledger, pub_alice, &acc_alice) == SC_OK);
    CHECK(acc_alice.balance == 1000);
    CHECK(acc_alice.nonce == 0);

    /* Non-strict execution: applies tx 0 and tx 1, skips tx 2 */
    rc = ledger_apply_block(ledger, txs, 3, false, &applied);
    CHECK(rc == SC_OK);
    CHECK(applied == 2);

    CHECK(ledger_get_account(ledger, pub_alice, &acc_alice) == SC_OK);
    CHECK(acc_alice.balance == 400);
    CHECK(acc_alice.nonce == 2);

    ledger_free(ledger);
    crypto_keypair_free(kp_alice);
    crypto_keypair_free(kp_bob);
}

static void test_deterministic_state_hash(void)
{
    /* Simulate Node 0 and Node 1 running separate ledgers */
    sc_ledger_t *node0_ledger = NULL;
    sc_ledger_t *node1_ledger = NULL;

    CHECK(ledger_create(&node0_ledger) == SC_OK);
    CHECK(ledger_create(&node1_ledger) == SC_OK);

    sc_keypair_t *kp[4];
    uint8_t pubs[4][SC_ED25519_PUBKEY_LEN];
    for (int i = 0; i < 4; i++) {
        CHECK(crypto_keygen(&kp[i]) == SC_OK);
        CHECK(crypto_get_pubkey(kp[i], pubs[i]) == SC_OK);
    }

    /* Initialize genesis on Node 0 in order 0, 1, 2, 3 */
    for (int i = 0; i < 4; i++) {
        CHECK(ledger_set_account(node0_ledger, pubs[i], (uint64_t)(10000 * (i + 1)), 0) == SC_OK);
    }

    /* Initialize genesis on Node 1 in reverse order 3, 2, 1, 0 */
    for (int i = 3; i >= 0; i--) {
        CHECK(ledger_set_account(node1_ledger, pubs[i], (uint64_t)(10000 * (i + 1)), 0) == SC_OK);
    }

    /* Initial state hashes must be 100% IDENTICAL despite reverse insertion order */
    uint8_t hash0[SC_SHA256_LEN];
    uint8_t hash1[SC_SHA256_LEN];
    CHECK(ledger_compute_state_hash(node0_ledger, hash0) == SC_OK);
    CHECK(ledger_compute_state_hash(node1_ledger, hash1) == SC_OK);
    CHECK(memcmp(hash0, hash1, SC_SHA256_LEN) == 0);

    /* Generate a series of 5 transactions across various accounts */
    sc_tx_t txs[5];
    CHECK(tx_create(&txs[0], kp[0], pubs[1], 1500, 10, 0) == SC_OK);
    CHECK(tx_create(&txs[1], kp[1], pubs[2], 2500, 20, 0) == SC_OK);
    CHECK(tx_create(&txs[2], kp[2], pubs[3], 500,  5,  0) == SC_OK);
    CHECK(tx_create(&txs[3], kp[0], pubs[3], 800,  10, 1) == SC_OK);
    CHECK(tx_create(&txs[4], kp[3], pubs[0], 1200, 15, 0) == SC_OK);

    /* Apply block on Node 0 */
    size_t applied0 = 0;
    CHECK(ledger_apply_block(node0_ledger, txs, 5, true, &applied0) == SC_OK);
    CHECK(applied0 == 5);

    /* Apply same block on Node 1 */
    size_t applied1 = 0;
    CHECK(ledger_apply_block(node1_ledger, txs, 5, true, &applied1) == SC_OK);
    CHECK(applied1 == 5);

    /* Recompute post-execution state hashes */
    CHECK(ledger_compute_state_hash(node0_ledger, hash0) == SC_OK);
    CHECK(ledger_compute_state_hash(node1_ledger, hash1) == SC_OK);

    /* State hash MUST match byte-for-byte on both nodes */
    CHECK(memcmp(hash0, hash1, SC_SHA256_LEN) == 0);

    /* Verify sensitivity: tamper with 1 token on Node 1 */
    sc_account_t acc0;
    CHECK(ledger_get_account(node1_ledger, pubs[0], &acc0) == SC_OK);
    CHECK(ledger_set_account(node1_ledger, pubs[0], acc0.balance + 1, acc0.nonce) == SC_OK);

    CHECK(ledger_compute_state_hash(node1_ledger, hash1) == SC_OK);
    /* Hashes must now diverge completely */
    CHECK(memcmp(hash0, hash1, SC_SHA256_LEN) != 0);

    ledger_free(node0_ledger);
    ledger_free(node1_ledger);
    for (int i = 0; i < 4; i++) {
        crypto_keypair_free(kp[i]);
    }
}

int main(void)
{
    log_init(-1);
    printf("test_ledger\n");
    RUN(test_genesis_and_lookup);
    RUN(test_valid_transfer_execution);
    RUN(test_insufficient_balance_rejected);
    RUN(test_nonce_ordering_enforced);
    RUN(test_forged_sig_rejected);
    RUN(test_self_transfer);
    RUN(test_strict_batch_rollback);
    RUN(test_deterministic_state_hash);
    return TEST_SUMMARY();
}
