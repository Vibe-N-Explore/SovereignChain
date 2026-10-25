/* test_storage.c - unit tests for atomic persistence and crash recovery. */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "crypto.h"
#include "err.h"
#include "ledger.h"
#include "log.h"
#include "storage.h"
#include "testutil.h"

static void test_save_and_load_roundtrip(void)
{
    sc_ledger_t *l_orig = NULL;
    CHECK(ledger_create(&l_orig) == SC_OK);

    sc_keypair_t *kp[3];
    uint8_t pubs[3][SC_ED25519_PUBKEY_LEN];
    for (int i = 0; i < 3; i++) {
        CHECK(crypto_keygen(&kp[i]) == SC_OK);
        CHECK(crypto_get_pubkey(kp[i], pubs[i]) == SC_OK);
        CHECK(ledger_set_account(l_orig, pubs[i], (uint64_t)(1000 * (i + 1)), (uint64_t)i) == SC_OK);
    }

    uint8_t hash_orig[SC_SHA256_LEN];
    CHECK(ledger_compute_state_hash(l_orig, hash_orig) == SC_OK);

    const char *test_dir = "build/test_storage_dir";
    char err[128];
    CHECK(storage_save_state(l_orig, test_dir, err, sizeof(err)) == SC_OK);
    CHECK(storage_state_exists(test_dir));

    /* Load into completely fresh ledger */
    sc_ledger_t *l_loaded = NULL;
    CHECK(ledger_create(&l_loaded) == SC_OK);
    CHECK(storage_load_state(l_loaded, test_dir, err, sizeof(err)) == SC_OK);

    CHECK(ledger_account_count(l_loaded) == 3);

    for (int i = 0; i < 3; i++) {
        sc_account_t acc;
        CHECK(ledger_get_account(l_loaded, pubs[i], &acc) == SC_OK);
        CHECK(acc.balance == (uint64_t)(1000 * (i + 1)));
        CHECK(acc.nonce == (uint64_t)i);
    }

    uint8_t hash_loaded[SC_SHA256_LEN];
    CHECK(ledger_compute_state_hash(l_loaded, hash_loaded) == SC_OK);
    CHECK(memcmp(hash_orig, hash_loaded, SC_SHA256_LEN) == 0);

    ledger_free(l_orig);
    ledger_free(l_loaded);
    for (int i = 0; i < 3; i++) {
        crypto_keypair_free(kp[i]);
    }
}

static void test_corrupt_state_checksum_rejected(void)
{
    sc_ledger_t *l = NULL;
    CHECK(ledger_create(&l) == SC_OK);

    sc_keypair_t *kp = NULL;
    CHECK(crypto_keygen(&kp) == SC_OK);
    uint8_t pub[SC_ED25519_PUBKEY_LEN];
    CHECK(crypto_get_pubkey(kp, pub) == SC_OK);
    CHECK(ledger_set_account(l, pub, 99999, 5) == SC_OK);

    const char *test_dir = "build/test_storage_corrupt";
    char err[128];
    CHECK(storage_save_state(l, test_dir, err, sizeof(err)) == SC_OK);

    /* Corrupt a byte in state.dat (modify balance) */
    char path[512];
    snprintf(path, sizeof(path), "%s/state.dat", test_dir);
    FILE *f = fopen(path, "r+b");
    CHECK(f != NULL);
    fseek(f, 48 + 32, SEEK_SET); /* Into the balance field */
    int byte = fgetc(f);
    fseek(f, -1, SEEK_CUR);
    fputc(byte ^ 0xFF, f);
    fclose(f);

    /* Attempt load: must be rejected with invalid checksum */
    sc_ledger_t *l_bad = NULL;
    CHECK(ledger_create(&l_bad) == SC_OK);
    sc_err_t rc = storage_load_state(l_bad, test_dir, err, sizeof(err));
    CHECK(rc == SC_ERR_INVALID);
    CHECK_CONTAINS(err, "corrupt_state_checksum_mismatch");

    ledger_free(l);
    ledger_free(l_bad);
    crypto_keypair_free(kp);
}

static void test_load_non_existent(void)
{
    sc_ledger_t *l = NULL;
    CHECK(ledger_create(&l) == SC_OK);

    char err[128];
    CHECK(storage_load_state(l, "build/non_existent_dir_999", err, sizeof(err)) == SC_ERR_NOT_FOUND);

    ledger_free(l);
}

int main(void)
{
    log_init(-1);
    printf("test_storage\n");
    RUN(test_save_and_load_roundtrip);
    RUN(test_corrupt_state_checksum_rejected);
    RUN(test_load_non_existent);
    return TEST_SUMMARY();
}
