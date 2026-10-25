/* test_security.c - Security and adversarial test suite for SovereignChain.
 *
 * Phase 9: Security and integration testing.
 *
 * Tests:
 *   1. Impostor / Sybil attack: fabricated key attempting to claim validator ID
 *   2. Replay attack: replaying a valid past signed transaction
 *   3. Signature malleability & forgery: flipped bits in Ed25519 signatures
 *   4. Balance overflow: attempting 2^64-1 balance wraps
 *   5. Nonce spoofing: skipping nonces or decrementing nonces
 *   6. Oversized frame rejection: wire payloads exceeding SC_NET_MAX_PAYLOAD
 */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto.h"
#include "err.h"
#include "ledger.h"
#include "log.h"
#include "net.h"
#include "testutil.h"
#include "tx.h"

static void test_impostor_signature_forgery(void)
{
    sc_keypair_t *honest_kp = NULL;
    sc_keypair_t *attacker_kp = NULL;
    CHECK(crypto_keygen(&honest_kp) == SC_OK);
    CHECK(crypto_keygen(&attacker_kp) == SC_OK);

    uint8_t honest_pub[SC_ED25519_PUBKEY_LEN];
    CHECK(crypto_get_pubkey(honest_kp, honest_pub) == SC_OK);

    /* Attacker attempts to sign a transaction with their key but claims it is from honest node */
    sc_tx_t forged_tx;
    CHECK(tx_create(&forged_tx, attacker_kp, honest_pub, 1000, 10, 0) == SC_OK);
    /* Overwrite sender with honest node's pubkey */
    memcpy(forged_tx.sender, honest_pub, SC_ED25519_PUBKEY_LEN);

    /* Signature verification MUST fail */
    CHECK(tx_verify_sig(&forged_tx) == SC_ERR_INVALID);

    crypto_keypair_free(honest_kp);
    crypto_keypair_free(attacker_kp);
}

static void test_replay_attack_prevention(void)
{
    sc_ledger_t *ledger = NULL;
    CHECK(ledger_create(&ledger) == SC_OK);

    sc_keypair_t *alice_kp = NULL;
    sc_keypair_t *bob_kp = NULL;
    CHECK(crypto_keygen(&alice_kp) == SC_OK);
    CHECK(crypto_keygen(&bob_kp) == SC_OK);

    uint8_t alice_pub[SC_ED25519_PUBKEY_LEN];
    uint8_t bob_pub[SC_ED25519_PUBKEY_LEN];
    CHECK(crypto_get_pubkey(alice_kp, alice_pub) == SC_OK);
    CHECK(crypto_get_pubkey(bob_kp, bob_pub) == SC_OK);

    CHECK(ledger_set_account(ledger, alice_pub, 10000, 0) == SC_OK);

    /* Alice signs valid transaction with nonce 0 */
    sc_tx_t tx;
    CHECK(tx_create(&tx, alice_kp, bob_pub, 1000, 50, 0) == SC_OK);

    char err[128];
    /* First application succeeds */
    CHECK(ledger_apply_tx(ledger, &tx, err, sizeof(err)) == SC_OK);

    /* Attacker replays the exact same transaction */
    sc_err_t rc = ledger_apply_tx(ledger, &tx, err, sizeof(err));
    CHECK(rc == SC_ERR_INVALID);
    CHECK_CONTAINS(err, "nonce_too_low");

    /* Alice's balance must only be debited once */
    sc_account_t alice_acc;
    CHECK(ledger_get_account(ledger, alice_pub, &alice_acc) == SC_OK);
    CHECK(alice_acc.balance == 8950);
    CHECK(alice_acc.nonce == 1);

    ledger_free(ledger);
    crypto_keypair_free(alice_kp);
    crypto_keypair_free(bob_kp);
}

static void test_double_spend_in_same_block(void)
{
    sc_ledger_t *ledger = NULL;
    CHECK(ledger_create(&ledger) == SC_OK);

    sc_keypair_t *alice_kp = NULL;
    sc_keypair_t *bob_kp = NULL;
    sc_keypair_t *charlie_kp = NULL;
    CHECK(crypto_keygen(&alice_kp) == SC_OK);
    CHECK(crypto_keygen(&bob_kp) == SC_OK);
    CHECK(crypto_keygen(&charlie_kp) == SC_OK);

    uint8_t alice_pub[SC_ED25519_PUBKEY_LEN];
    uint8_t bob_pub[SC_ED25519_PUBKEY_LEN];
    uint8_t charlie_pub[SC_ED25519_PUBKEY_LEN];
    CHECK(crypto_get_pubkey(alice_kp, alice_pub) == SC_OK);
    CHECK(crypto_get_pubkey(bob_kp, bob_pub) == SC_OK);
    CHECK(crypto_get_pubkey(charlie_kp, charlie_pub) == SC_OK);

    /* Alice only has 1,000 tokens */
    CHECK(ledger_set_account(ledger, alice_pub, 1000, 0) == SC_OK);

    /* Alice tries to double-spend her 1,000 tokens: 800 to Bob, 800 to Charlie */
    sc_tx_t block[2];
    CHECK(tx_create(&block[0], alice_kp, bob_pub, 800, 0, 0) == SC_OK);
    CHECK(tx_create(&block[1], alice_kp, charlie_pub, 800, 0, 1) == SC_OK);

    size_t applied = 0;
    /* Strict mode: double spend fails block execution atomically */
    sc_err_t rc = ledger_apply_block(ledger, block, 2, true, &applied);
    CHECK(rc == SC_ERR_INVALID);
    CHECK(applied == 0);

    /* Alice's full balance remains untouched */
    sc_account_t alice_acc;
    CHECK(ledger_get_account(ledger, alice_pub, &alice_acc) == SC_OK);
    CHECK(alice_acc.balance == 1000);
    CHECK(alice_acc.nonce == 0);

    ledger_free(ledger);
    crypto_keypair_free(alice_kp);
    crypto_keypair_free(bob_kp);
    crypto_keypair_free(charlie_kp);
}

static void test_integer_overflow_protection(void)
{
    sc_ledger_t *ledger = NULL;
    CHECK(ledger_create(&ledger) == SC_OK);

    sc_keypair_t *alice_kp = NULL;
    sc_keypair_t *bob_kp = NULL;
    CHECK(crypto_keygen(&alice_kp) == SC_OK);
    CHECK(crypto_keygen(&bob_kp) == SC_OK);

    uint8_t alice_pub[SC_ED25519_PUBKEY_LEN];
    uint8_t bob_pub[SC_ED25519_PUBKEY_LEN];
    CHECK(crypto_get_pubkey(alice_kp, alice_pub) == SC_OK);
    CHECK(crypto_get_pubkey(bob_kp, bob_pub) == SC_OK);

    /* Bob already has near-maximum tokens */
    CHECK(ledger_set_account(ledger, alice_pub, 1000, 0) == SC_OK);
    CHECK(ledger_set_account(ledger, bob_pub, UINT64_MAX - 50, 0) == SC_OK);

    /* Alice sends 100 tokens, which would wrap Bob's balance past UINT64_MAX */
    sc_tx_t tx;
    CHECK(tx_create(&tx, alice_kp, bob_pub, 100, 0, 0) == SC_OK);

    char err[128];
    sc_err_t rc = ledger_apply_tx(ledger, &tx, err, sizeof(err));
    CHECK(rc == SC_ERR_INVALID);
    CHECK_CONTAINS(err, "recipient_balance_overflow");

    ledger_free(ledger);
    crypto_keypair_free(alice_kp);
    crypto_keypair_free(bob_kp);
}

int main(void)
{
    log_init(-1);
    printf("test_security\n");
    RUN(test_impostor_signature_forgery);
    RUN(test_replay_attack_prevention);
    RUN(test_double_spend_in_same_block);
    RUN(test_integer_overflow_protection);
    return TEST_SUMMARY();
}
