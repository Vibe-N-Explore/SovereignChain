/* test_cn_rate.c - Unit tests for rate validation, signing, verification, and persistence. */
#define _POSIX_C_SOURCE 200809L

#include "testutil.h"
#include "cn_rate.h"
#include "connector_types.h"
#include "../../src/crypto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void cleanup_dir(const char *dir)
{
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", dir);
    if (system(cmd)) {}
}

static void test_rate_validation(void)
{
    cn_rate_t r;
    memset(&r, 0, sizeof(r));

    r.rate_num = 1;
    r.rate_den = 1;
    CHECK(cn_rate_validate(&r) == SC_OK);

    r.rate_den = 0;
    CHECK(cn_rate_validate(&r) == SC_ERR_INVALID);

    r.rate_den = 1;
    r.rate_num = 0;
    CHECK(cn_rate_validate(&r) == SC_ERR_INVALID);

    /* Absurd rate */
    r.rate_num = 100000000ULL;
    r.rate_den = 1ULL;
    CHECK(cn_rate_validate(&r) == SC_ERR_INVALID);
}

static void test_rate_signing_and_verification(void)
{
    sc_keypair_t *kp = NULL;
    CHECK(crypto_keygen(&kp) == SC_OK);

    cn_rate_t rate;
    memset(&rate, 0, sizeof(rate));
    rate.rate_num = 5;
    rate.rate_den = 4;
    rate.version = 3;

    CHECK(cn_rate_sign(&rate, kp) == SC_OK);
    CHECK(rate.updated_at > 0);
    CHECK(cn_rate_verify(&rate) == SC_OK);

    /* Tamper with numerator */
    rate.rate_num = 6;
    CHECK(cn_rate_verify(&rate) != SC_OK);
    rate.rate_num = 5;

    /* Tamper with version */
    rate.version = 4;
    CHECK(cn_rate_verify(&rate) != SC_OK);
    rate.version = 3;

    /* Verify again restores OK */
    CHECK(cn_rate_verify(&rate) == SC_OK);

    crypto_keypair_free(kp);
}

static void test_rate_persistence(void)
{
    const char *test_dir = "/tmp/test_cn_rate_persist";
    cleanup_dir(test_dir);

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "mkdir -p %s", test_dir);
    if (system(cmd)) {}

    sc_keypair_t *kp = NULL;
    CHECK(crypto_keygen(&kp) == SC_OK);

    cn_rate_t a_to_b;
    memset(&a_to_b, 0, sizeof(a_to_b));
    a_to_b.rate_num = 2;
    a_to_b.rate_den = 1;
    a_to_b.version = 1;
    CHECK(cn_rate_sign(&a_to_b, kp) == SC_OK);

    cn_rate_t b_to_a;
    memset(&b_to_a, 0, sizeof(b_to_a));
    b_to_a.rate_num = 1;
    b_to_a.rate_den = 2;
    b_to_a.version = 1;
    CHECK(cn_rate_sign(&b_to_a, kp) == SC_OK);

    CHECK(cn_rate_save(&a_to_b, &b_to_a, test_dir) == SC_OK);

    cn_rate_t loaded_a_to_b, loaded_b_to_a;
    memset(&loaded_a_to_b, 0, sizeof(loaded_a_to_b));
    memset(&loaded_b_to_a, 0, sizeof(loaded_b_to_a));

    CHECK(cn_rate_load(&loaded_a_to_b, &loaded_b_to_a, test_dir) == SC_OK);

    CHECK(loaded_a_to_b.rate_num == 2);
    CHECK(loaded_a_to_b.rate_den == 1);
    CHECK(loaded_a_to_b.version == 1);
    CHECK(cn_rate_verify(&loaded_a_to_b) == SC_OK);

    CHECK(loaded_b_to_a.rate_num == 1);
    CHECK(loaded_b_to_a.rate_den == 2);
    CHECK(loaded_b_to_a.version == 1);
    CHECK(cn_rate_verify(&loaded_b_to_a) == SC_OK);

    crypto_keypair_free(kp);
    cleanup_dir(test_dir);
}

int main(void)
{
    printf("test_cn_rate:\n");
    RUN(test_rate_validation);
    RUN(test_rate_signing_and_verification);
    RUN(test_rate_persistence);
    return TEST_SUMMARY();
}
