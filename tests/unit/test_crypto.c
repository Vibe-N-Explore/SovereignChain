#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "crypto.h"
#include "testutil.h"

/* ------------------------------------------------------------------ */
/* SHA-256 tests                                                       */
/* ------------------------------------------------------------------ */

static void test_sha256_empty(void)
{
    /* SHA-256("") is a well-known fixed value — easy to verify externally
     * with: echo -n "" | sha256sum */
    uint8_t hash[SC_SHA256_LEN];
    const uint8_t expected[SC_SHA256_LEN] = {
        0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14,
        0x9a,0xfb,0xf4,0xc8,0x99,0x6f,0xb9,0x24,
        0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c,
        0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55
    };
    CHECK(crypto_sha256("", 0, hash) == SC_OK);
    CHECK(memcmp(hash, expected, SC_SHA256_LEN) == 0);
}

static void test_sha256_abc(void)
{
    /* SHA-256("abc") is another well-known value */
    uint8_t hash[SC_SHA256_LEN];
    const uint8_t expected[SC_SHA256_LEN] = {
        0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,
        0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
        0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,
        0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad
    };
    CHECK(crypto_sha256("abc", 3, hash) == SC_OK);
    CHECK(memcmp(hash, expected, SC_SHA256_LEN) == 0);
}

static void test_sha256_deterministic(void)
{
    /* Same input must always produce the same output — crypto property. */
    uint8_t h1[SC_SHA256_LEN], h2[SC_SHA256_LEN];
    const char *msg = "SovereignChain test message";
    CHECK(crypto_sha256(msg, strlen(msg), h1) == SC_OK);
    CHECK(crypto_sha256(msg, strlen(msg), h2) == SC_OK);
    CHECK(memcmp(h1, h2, SC_SHA256_LEN) == 0);
}

static void test_sha256_different_inputs(void)
{
    /* Different inputs must produce different hashes (with overwhelming prob.) */
    uint8_t h1[SC_SHA256_LEN], h2[SC_SHA256_LEN];
    CHECK(crypto_sha256("hello", 5, h1) == SC_OK);
    CHECK(crypto_sha256("world", 5, h2) == SC_OK);
    CHECK(memcmp(h1, h2, SC_SHA256_LEN) != 0);
}

/* ------------------------------------------------------------------ */
/* Hex encode/decode tests                                             */
/* ------------------------------------------------------------------ */

static void test_hex_roundtrip(void)
{
    uint8_t bin[16];
    char hex[33];
    uint8_t decoded[16];

    /* Fill with known values */
    for (size_t i = 0; i < 16; i++)
        bin[i] = (uint8_t)i;

    crypto_hex_encode(bin, 16, hex);
    CHECK(strcmp(hex, "000102030405060708090a0b0c0d0e0f") == 0);
    CHECK(crypto_hex_decode(hex, decoded, 16));
    CHECK(memcmp(bin, decoded, 16) == 0);
}

static void test_hex_uppercase_decode(void)
{
    /* Decoder must accept uppercase A-F too */
    uint8_t out[4];
    CHECK(crypto_hex_decode("DEADBEEF", out, 4));
    CHECK(out[0] == 0xde && out[1] == 0xad &&
          out[2] == 0xbe && out[3] == 0xef);
}

static void test_hex_bad_inputs(void)
{
    uint8_t out[4];
    CHECK(!crypto_hex_decode("ZZZZ", out, 4));      /* invalid chars  */
    CHECK(!crypto_hex_decode("abc", out, 4));         /* odd length     */
    CHECK(!crypto_hex_decode("abcd", out, 4));        /* right length: ok */
    CHECK(crypto_hex_decode("abcd0011", out, 4));     /* 8 chars for 4 bytes: ok */
    CHECK(!crypto_hex_decode("abcd001100", out, 4));  /* too long       */
}

/* ------------------------------------------------------------------ */
/* Key generation & introspection tests                               */
/* ------------------------------------------------------------------ */

static void test_keygen(void)
{
    sc_keypair_t *kp = NULL;
    CHECK(crypto_keygen(&kp) == SC_OK);
    CHECK(kp != NULL);
    CHECK(crypto_has_private(kp));

    uint8_t pub[SC_ED25519_PUBKEY_LEN];
    CHECK(crypto_get_pubkey(kp, pub) == SC_OK);
    /* Public key should not be all-zero (astronomically unlikely) */
    int allzero = 1;
    for (int i = 0; i < SC_ED25519_PUBKEY_LEN; i++)
        if (pub[i]) { allzero = 0; break; }
    CHECK(!allzero);

    crypto_keypair_free(kp);
}

static void test_keygen_two_distinct(void)
{
    /* Two independently generated keypairs must have different public keys */
    sc_keypair_t *kp1 = NULL, *kp2 = NULL;
    uint8_t pub1[SC_ED25519_PUBKEY_LEN], pub2[SC_ED25519_PUBKEY_LEN];

    CHECK(crypto_keygen(&kp1) == SC_OK);
    CHECK(crypto_keygen(&kp2) == SC_OK);
    CHECK(crypto_get_pubkey(kp1, pub1) == SC_OK);
    CHECK(crypto_get_pubkey(kp2, pub2) == SC_OK);
    CHECK(memcmp(pub1, pub2, SC_ED25519_PUBKEY_LEN) != 0);

    crypto_keypair_free(kp1);
    crypto_keypair_free(kp2);
}

static void test_pubkey_from_raw(void)
{
    /* Generate a keypair, extract pubkey, create public-only handle */
    sc_keypair_t *full_kp = NULL, *pub_kp = NULL;
    uint8_t pub[SC_ED25519_PUBKEY_LEN], pub2[SC_ED25519_PUBKEY_LEN];

    CHECK(crypto_keygen(&full_kp) == SC_OK);
    CHECK(crypto_get_pubkey(full_kp, pub) == SC_OK);

    CHECK(crypto_pubkey_from_raw(&pub_kp, pub) == SC_OK);
    CHECK(!crypto_has_private(pub_kp));           /* public-only: no private */
    CHECK(crypto_get_pubkey(pub_kp, pub2) == SC_OK);
    CHECK(memcmp(pub, pub2, SC_ED25519_PUBKEY_LEN) == 0);

    crypto_keypair_free(full_kp);
    crypto_keypair_free(pub_kp);
}

/* ------------------------------------------------------------------ */
/* Signing and verification tests                                     */
/* ------------------------------------------------------------------ */

static void test_sign_and_verify(void)
{
    sc_keypair_t *kp = NULL;
    uint8_t sig[SC_ED25519_SIG_LEN];
    const char *msg = "hello SovereignChain";

    CHECK(crypto_keygen(&kp) == SC_OK);
    CHECK(crypto_sign(kp, msg, strlen(msg), sig) == SC_OK);
    CHECK(crypto_verify(kp, msg, strlen(msg), sig) == SC_OK);

    crypto_keypair_free(kp);
}

static void test_verify_wrong_message(void)
{
    /* Changing even one byte of the message must invalidate the signature */
    sc_keypair_t *kp = NULL;
    uint8_t sig[SC_ED25519_SIG_LEN];
    const char *msg1 = "correct message";
    const char *msg2 = "correct Message"; /* capital M */

    CHECK(crypto_keygen(&kp) == SC_OK);
    CHECK(crypto_sign(kp, msg1, strlen(msg1), sig) == SC_OK);
    CHECK(crypto_verify(kp, msg2, strlen(msg2), sig) == SC_ERR_INVALID);

    crypto_keypair_free(kp);
}

static void test_verify_tampered_signature(void)
{
    sc_keypair_t *kp = NULL;
    uint8_t sig[SC_ED25519_SIG_LEN];
    const char *msg = "important message";

    CHECK(crypto_keygen(&kp) == SC_OK);
    CHECK(crypto_sign(kp, msg, strlen(msg), sig) == SC_OK);

    /* Flip one bit in the middle of the signature */
    sig[32] ^= 0x01;
    CHECK(crypto_verify(kp, msg, strlen(msg), sig) == SC_ERR_INVALID);

    crypto_keypair_free(kp);
}

static void test_verify_wrong_key(void)
{
    /* Signature under key1 must NOT verify under key2 */
    sc_keypair_t *kp1 = NULL, *kp2 = NULL;
    uint8_t sig[SC_ED25519_SIG_LEN];
    const char *msg = "cross-key forgery attempt";

    CHECK(crypto_keygen(&kp1) == SC_OK);
    CHECK(crypto_keygen(&kp2) == SC_OK);
    CHECK(crypto_sign(kp1, msg, strlen(msg), sig) == SC_OK);
    CHECK(crypto_verify(kp2, msg, strlen(msg), sig) == SC_ERR_INVALID);

    crypto_keypair_free(kp1);
    crypto_keypair_free(kp2);
}

static void test_sign_then_verify_with_pubonly(void)
{
    /* After exporting the pubkey and creating a public-only handle,
     * verification must still work (this is the normal use in net.c). */
    sc_keypair_t *full_kp = NULL, *pub_kp = NULL;
    uint8_t sig[SC_ED25519_SIG_LEN];
    uint8_t pub[SC_ED25519_PUBKEY_LEN];
    const char *msg = "verifying with public-only handle";

    CHECK(crypto_keygen(&full_kp) == SC_OK);
    CHECK(crypto_sign(full_kp, msg, strlen(msg), sig) == SC_OK);
    CHECK(crypto_get_pubkey(full_kp, pub) == SC_OK);

    /* Build a verify-only handle — simulates how a peer verifies our sig */
    CHECK(crypto_pubkey_from_raw(&pub_kp, pub) == SC_OK);
    CHECK(crypto_verify(pub_kp, msg, strlen(msg), sig) == SC_OK);

    /* Public-only handle cannot sign */
    uint8_t sig2[SC_ED25519_SIG_LEN];
    CHECK(crypto_sign(pub_kp, msg, strlen(msg), sig2) == SC_ERR_INVALID);

    crypto_keypair_free(full_kp);
    crypto_keypair_free(pub_kp);
}

static void test_sign_empty_message(void)
{
    /* Edge case: sign a zero-length message */
    sc_keypair_t *kp = NULL;
    uint8_t sig[SC_ED25519_SIG_LEN];

    CHECK(crypto_keygen(&kp) == SC_OK);
    CHECK(crypto_sign(kp, "", 0, sig) == SC_OK);
    CHECK(crypto_verify(kp, "", 0, sig) == SC_OK);
    CHECK(crypto_verify(kp, "x", 1, sig) == SC_ERR_INVALID);

    crypto_keypair_free(kp);
}

static void test_deterministic_signature(void)
{
    /* Ed25519 is deterministic: same key + same message = same signature.
     * This is a design property of EdDSA, unlike ECDSA which needs a
     * fresh random nonce per signature (a source of many historical bugs). */
    sc_keypair_t *kp = NULL;
    uint8_t sig1[SC_ED25519_SIG_LEN], sig2[SC_ED25519_SIG_LEN];
    const char *msg = "determinism test";

    CHECK(crypto_keygen(&kp) == SC_OK);
    CHECK(crypto_sign(kp, msg, strlen(msg), sig1) == SC_OK);
    CHECK(crypto_sign(kp, msg, strlen(msg), sig2) == SC_OK);
    CHECK(memcmp(sig1, sig2, SC_ED25519_SIG_LEN) == 0);

    crypto_keypair_free(kp);
}

/* ------------------------------------------------------------------ */
/* Random bytes test                                                   */
/* ------------------------------------------------------------------ */

static void test_rand_bytes_not_zero(void)
{
    /* CSPRNG output should not be all-zero (astronomically unlikely) */
    uint8_t buf1[32], buf2[32];
    CHECK(crypto_rand_bytes(buf1, 32) == SC_OK);
    CHECK(crypto_rand_bytes(buf2, 32) == SC_OK);

    /* Two fresh 32-byte random values must differ (prob ~1/2^256 of collision) */
    CHECK(memcmp(buf1, buf2, 32) != 0);

    /* Sanity: not all zeros */
    int allzero = 1;
    for (int i = 0; i < 32; i++) if (buf1[i]) { allzero = 0; break; }
    CHECK(!allzero);
}

/* ------------------------------------------------------------------ */
/* Key save/load test (uses a temp file)                               */
/* ------------------------------------------------------------------ */

static void test_key_save_load_roundtrip(void)
{
    sc_keypair_t *orig = NULL, *loaded = NULL;
    uint8_t pub_orig[SC_ED25519_PUBKEY_LEN], pub_loaded[SC_ED25519_PUBKEY_LEN];
    uint8_t sig_orig[SC_ED25519_SIG_LEN], sig_loaded[SC_ED25519_SIG_LEN];
    char path[64] = "/tmp/sc_test_key_XXXXXX";
    char err[256];
    int fd;

    /* Create a temp file path (mkstemp gives us the fd; we close it and
     * let crypto_save_privkey reopen for writing in PEM mode). */
    fd = mkstemp(path);
    if (fd < 0) {
        fprintf(stderr, "  SKIP test_key_save_load_roundtrip: mkstemp failed\n");
        return;
    }
    close(fd);

    CHECK(crypto_keygen(&orig) == SC_OK);
    CHECK(crypto_get_pubkey(orig, pub_orig) == SC_OK);
    CHECK(crypto_save_privkey(orig, path) == SC_OK);

    CHECK(crypto_load_privkey(&loaded, path, err, sizeof err) == SC_OK);
    CHECK(loaded != NULL);
    CHECK(crypto_has_private(loaded));
    CHECK(crypto_get_pubkey(loaded, pub_loaded) == SC_OK);
    CHECK(memcmp(pub_orig, pub_loaded, SC_ED25519_PUBKEY_LEN) == 0);

    /* Both keys must produce IDENTICAL signatures for the same message
     * (Ed25519 is deterministic). This confirms the private key survived
     * the PEM serialization round-trip exactly. */
    const char *msg = "round-trip test";
    CHECK(crypto_sign(orig,   msg, strlen(msg), sig_orig)   == SC_OK);
    CHECK(crypto_sign(loaded, msg, strlen(msg), sig_loaded) == SC_OK);
    CHECK(memcmp(sig_orig, sig_loaded, SC_ED25519_SIG_LEN) == 0);

    unlink(path);
    crypto_keypair_free(orig);
    crypto_keypair_free(loaded);
}

/* ------------------------------------------------------------------ */
/* Simulate the handshake exchange in isolation                        */
/*                                                                     */
/* This is the most important test in Phase 3: it verifies that the   */
/* core cryptographic protocol of our handshake (sign nonce, verify)  */
/* works correctly before we exercise it over sockets.                */
/* ------------------------------------------------------------------ */

static void test_handshake_simulation(void)
{
    /* Simulate what net.c does during the challenge-response handshake:
     *
     *   Listener generates nonce, signs it, sends nonce+sig to connector.
     *   Connector verifies listener's sig, signs same nonce, replies.
     *   Listener verifies connector's sig.
     *
     * We test both the happy path and the impostor path.
     */

    /* Listener */
    sc_keypair_t *listener_kp = NULL;
    uint8_t listener_pub[SC_ED25519_PUBKEY_LEN];
    uint8_t nonce[SC_NONCE_LEN];
    uint8_t listener_sig[SC_ED25519_SIG_LEN];

    /* Connector */
    sc_keypair_t *connector_kp = NULL;
    uint8_t connector_pub[SC_ED25519_PUBKEY_LEN];
    uint8_t connector_sig[SC_ED25519_SIG_LEN];

    /* Impostor */
    sc_keypair_t *impostor_kp = NULL;
    uint8_t impostor_sig[SC_ED25519_SIG_LEN];

    CHECK(crypto_keygen(&listener_kp)   == SC_OK);
    CHECK(crypto_keygen(&connector_kp)  == SC_OK);
    CHECK(crypto_keygen(&impostor_kp)   == SC_OK);
    CHECK(crypto_get_pubkey(listener_kp,  listener_pub)  == SC_OK);
    CHECK(crypto_get_pubkey(connector_kp, connector_pub) == SC_OK);

    /* Step 1: Listener generates nonce and signs it */
    CHECK(crypto_rand_bytes(nonce, SC_NONCE_LEN) == SC_OK);
    CHECK(crypto_sign(listener_kp, nonce, SC_NONCE_LEN, listener_sig) == SC_OK);

    /* Step 2: Connector verifies listener's sig against listener's pinned pubkey */
    {
        sc_keypair_t *lkp_pub = NULL;
        CHECK(crypto_pubkey_from_raw(&lkp_pub, listener_pub) == SC_OK);
        CHECK(crypto_verify(lkp_pub, nonce, SC_NONCE_LEN, listener_sig) == SC_OK);
        crypto_keypair_free(lkp_pub);
    }

    /* Step 3: Connector signs the nonce and sends reply */
    CHECK(crypto_sign(connector_kp, nonce, SC_NONCE_LEN, connector_sig) == SC_OK);

    /* Step 4: Listener verifies connector's sig against connector's pinned pubkey */
    {
        sc_keypair_t *ckp_pub = NULL;
        CHECK(crypto_pubkey_from_raw(&ckp_pub, connector_pub) == SC_OK);
        CHECK(crypto_verify(ckp_pub, nonce, SC_NONCE_LEN, connector_sig) == SC_OK);
        crypto_keypair_free(ckp_pub);
    }

    /* Impostor attack: impostor signs the same nonce but with wrong key.
     * Verification against the pinned connector pubkey must FAIL. */
    CHECK(crypto_sign(impostor_kp, nonce, SC_NONCE_LEN, impostor_sig) == SC_OK);
    {
        sc_keypair_t *ckp_pub = NULL;
        CHECK(crypto_pubkey_from_raw(&ckp_pub, connector_pub) == SC_OK);
        /* Verifying impostor's sig against CONNECTOR's pubkey must fail */
        CHECK(crypto_verify(ckp_pub, nonce, SC_NONCE_LEN, impostor_sig) == SC_ERR_INVALID);
        crypto_keypair_free(ckp_pub);
    }

    crypto_keypair_free(listener_kp);
    crypto_keypair_free(connector_kp);
    crypto_keypair_free(impostor_kp);
}

/* ------------------------------------------------------------------ */
/* Null-safety tests                                                   */
/* ------------------------------------------------------------------ */

static void test_null_safety(void)
{
    crypto_keypair_free(NULL); /* must not crash (NULL-safe free) */
    CHECK(crypto_sha256(NULL, 0, NULL) == SC_ERR_INVALID);

    uint8_t hash[SC_SHA256_LEN];
    CHECK(crypto_sha256("x", 1, hash) == SC_OK);   /* normal use */
    CHECK(crypto_sha256(NULL, 1, hash) == SC_ERR_INVALID);

    CHECK(!crypto_hex_decode(NULL, NULL, 0));
}

/* ------------------------------------------------------------------ */
/* Main                                                                */
/* ------------------------------------------------------------------ */

int main(void)
{
    printf("test_crypto\n");
    RUN(test_sha256_empty);
    RUN(test_sha256_abc);
    RUN(test_sha256_deterministic);
    RUN(test_sha256_different_inputs);
    RUN(test_hex_roundtrip);
    RUN(test_hex_uppercase_decode);
    RUN(test_hex_bad_inputs);
    RUN(test_keygen);
    RUN(test_keygen_two_distinct);
    RUN(test_pubkey_from_raw);
    RUN(test_sign_and_verify);
    RUN(test_verify_wrong_message);
    RUN(test_verify_tampered_signature);
    RUN(test_verify_wrong_key);
    RUN(test_sign_then_verify_with_pubonly);
    RUN(test_sign_empty_message);
    RUN(test_deterministic_signature);
    RUN(test_rand_bytes_not_zero);
    RUN(test_key_save_load_roundtrip);
    RUN(test_handshake_simulation);
    RUN(test_null_safety);
    return TEST_SUMMARY();
}
