/* test_tx.c - unit tests for transaction creation, signing, serialization, and verification. */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto.h"
#include "err.h"
#include "log.h"
#include "testutil.h"
#include "tx.h"

static void test_tx_create_and_verify(void)
{
    sc_keypair_t *sender_kp = NULL;
    sc_keypair_t *recipient_kp = NULL;

    CHECK(crypto_keygen(&sender_kp) == SC_OK);
    CHECK(crypto_keygen(&recipient_kp) == SC_OK);

    uint8_t recipient_pub[SC_ED25519_PUBKEY_LEN];
    CHECK(crypto_get_pubkey(recipient_kp, recipient_pub) == SC_OK);

    sc_tx_t tx;
    CHECK(tx_create(&tx, sender_kp, recipient_pub, 1000, 10, 0) == SC_OK);
    CHECK(tx.amount == 1000);
    CHECK(tx.fee == 10);
    CHECK(tx.nonce == 0);

    /* Verify signature succeeds */
    CHECK(tx_verify_sig(&tx) == SC_OK);

    crypto_keypair_free(sender_kp);
    crypto_keypair_free(recipient_kp);
}

static void test_tx_tampered_sig_rejected(void)
{
    sc_keypair_t *sender_kp = NULL;
    sc_keypair_t *recipient_kp = NULL;

    CHECK(crypto_keygen(&sender_kp) == SC_OK);
    CHECK(crypto_keygen(&recipient_kp) == SC_OK);

    uint8_t recipient_pub[SC_ED25519_PUBKEY_LEN];
    CHECK(crypto_get_pubkey(recipient_kp, recipient_pub) == SC_OK);

    sc_tx_t tx;
    CHECK(tx_create(&tx, sender_kp, recipient_pub, 500, 5, 1) == SC_OK);
    CHECK(tx_verify_sig(&tx) == SC_OK);

    /* Tamper with amount */
    tx.amount = 501;
    CHECK(tx_verify_sig(&tx) == SC_ERR_INVALID);

    /* Restore amount, tamper with nonce */
    tx.amount = 500;
    tx.nonce = 2;
    CHECK(tx_verify_sig(&tx) == SC_ERR_INVALID);

    /* Restore nonce, flip 1 bit in signature */
    tx.nonce = 1;
    tx.sig[0] ^= 0x01;
    CHECK(tx_verify_sig(&tx) == SC_ERR_INVALID);

    crypto_keypair_free(sender_kp);
    crypto_keypair_free(recipient_kp);
}

static void test_tx_wire_serialization_roundtrip(void)
{
    sc_keypair_t *sender_kp = NULL;
    sc_keypair_t *recipient_kp = NULL;

    CHECK(crypto_keygen(&sender_kp) == SC_OK);
    CHECK(crypto_keygen(&recipient_kp) == SC_OK);

    uint8_t recipient_pub[SC_ED25519_PUBKEY_LEN];
    CHECK(crypto_get_pubkey(recipient_kp, recipient_pub) == SC_OK);

    sc_tx_t tx_orig;
    CHECK(tx_create(&tx_orig, sender_kp, recipient_pub, 250000, 100, 42) == SC_OK);

    uint8_t wire[200];
    size_t written = 0;
    CHECK(tx_serialize(&tx_orig, wire, sizeof(wire), &written) == SC_OK);
    CHECK(written == SC_TX_WIRE_LEN);

    sc_tx_t tx_deser;
    CHECK(tx_deserialize(&tx_deser, wire, written) == SC_OK);

    CHECK(memcmp(tx_orig.sender, tx_deser.sender, SC_ED25519_PUBKEY_LEN) == 0);
    CHECK(memcmp(tx_orig.recipient, tx_deser.recipient, SC_ED25519_PUBKEY_LEN) == 0);
    CHECK(tx_orig.amount == tx_deser.amount);
    CHECK(tx_orig.fee == tx_deser.fee);
    CHECK(tx_orig.nonce == tx_deser.nonce);
    CHECK(memcmp(tx_orig.sig, tx_deser.sig, SC_ED25519_SIG_LEN) == 0);
    CHECK(memcmp(tx_orig.hash, tx_deser.hash, SC_SHA256_LEN) == 0);

    /* Deserialized tx must also pass signature verification */
    CHECK(tx_verify_sig(&tx_deser) == SC_OK);

    crypto_keypair_free(sender_kp);
    crypto_keypair_free(recipient_kp);
}

static void test_tx_hash_deterministic(void)
{
    sc_keypair_t *sender_kp = NULL;
    sc_keypair_t *recipient_kp = NULL;

    CHECK(crypto_keygen(&sender_kp) == SC_OK);
    CHECK(crypto_keygen(&recipient_kp) == SC_OK);

    uint8_t recipient_pub[SC_ED25519_PUBKEY_LEN];
    CHECK(crypto_get_pubkey(recipient_kp, recipient_pub) == SC_OK);

    sc_tx_t tx1, tx2;
    CHECK(tx_create(&tx1, sender_kp, recipient_pub, 1234, 10, 0) == SC_OK);
    CHECK(tx_create(&tx2, sender_kp, recipient_pub, 1234, 10, 0) == SC_OK);

    CHECK(memcmp(tx1.hash, tx2.hash, SC_SHA256_LEN) == 0);

    crypto_keypair_free(sender_kp);
    crypto_keypair_free(recipient_kp);
}

int main(void)
{
    log_init(-1);
    printf("test_tx\n");
    RUN(test_tx_create_and_verify);
    RUN(test_tx_tampered_sig_rejected);
    RUN(test_tx_wire_serialization_roundtrip);
    RUN(test_tx_hash_deterministic);
    return TEST_SUMMARY();
}
