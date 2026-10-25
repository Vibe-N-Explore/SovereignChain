/* test_cn_transfer.c - Unit tests for transfer arithmetic, voting, and state machine. */
#define _POSIX_C_SOURCE 200809L

#include "testutil.h"
#include "cn_transfer.h"
#include "connector_types.h"
#include "../../src/crypto.h"

#include <string.h>

static void test_transfer_arithmetic(void)
{
    uint64_t dest = 0;

    /* 1:1 rate */
    CHECK(cn_transfer_calc_dest_amount(1000, 1, 1, &dest) == SC_OK);
    CHECK(dest == 1000);

    /* 3:2 rate (1.5x) */
    CHECK(cn_transfer_calc_dest_amount(1000, 3, 2, &dest) == SC_OK);
    CHECK(dest == 1500);

    /* 1:2 rate (0.5x) */
    CHECK(cn_transfer_calc_dest_amount(1001, 1, 2, &dest) == SC_OK);
    CHECK(dest == 500); /* integer floor */

    /* Rate den == 0 */
    CHECK(cn_transfer_calc_dest_amount(1000, 1, 0, &dest) == SC_ERR_INVALID);

    /* Large arithmetic within uint64 without early 64-bit overflow */
    uint64_t large_amt = 1000000000000000ULL; /* 10^15 */
    CHECK(cn_transfer_calc_dest_amount(large_amt, 50000, 25000, &dest) == SC_OK);
    CHECK(dest == large_amt * 2);

    /* Huge multiplication overflow exceeding uint64 max */
    CHECK(cn_transfer_calc_dest_amount(UINT64_MAX, 2, 1, &dest) == SC_ERR_INVALID);
}

static void test_transfer_state_machine_and_voting(void)
{
    sc_keypair_t *kp1 = NULL, *kp2 = NULL, *kp3 = NULL;
    CHECK(crypto_keygen(&kp1) == SC_OK);
    CHECK(crypto_keygen(&kp2) == SC_OK);
    CHECK(crypto_keygen(&kp3) == SC_OK);

    uint8_t pk1[32], pk2[32], pk3[32];
    crypto_get_pubkey(kp1, pk1);
    crypto_get_pubkey(kp2, pk2);
    crypto_get_pubkey(kp3, pk3);

    sc_tx_t source_tx;
    memset(&source_tx, 0, sizeof(source_tx));
    memset(source_tx.hash, 0x55, 32);
    memcpy(source_tx.sender, pk1, 32);
    memset(source_tx.recipient, 0x66, 32);
    source_tx.amount = 1000;
    source_tx.nonce = 1;

    cn_rate_t rate;
    memset(&rate, 0, sizeof(rate));
    rate.rate_num = 2;
    rate.rate_den = 1;
    rate.version = 1;

    cn_transfer_t xfr;
    CHECK(cn_transfer_create(&xfr, CN_CHAIN_A, &source_tx, &rate) == SC_OK);
    CHECK(xfr.state == CN_XFR_DETECTED);
    CHECK(xfr.dest_amount == 2000);
    CHECK(xfr.cert_sig_count == 0);

    /* Test transition */
    CHECK(cn_transfer_transition(&xfr, CN_XFR_SOURCE_VERIFIED, "verified on chain A") == SC_OK);
    CHECK(xfr.state == CN_XFR_SOURCE_VERIFIED);
    CHECK(strcmp(xfr.error_detail, "verified on chain A") == 0);

    /* Sign votes */
    uint8_t sig1[64], sig2[64];
    CHECK(cn_transfer_sign_vote(&xfr, kp1, sig1) == SC_OK);
    CHECK(cn_transfer_sign_vote(&xfr, kp2, sig2) == SC_OK);

    /* Verify single vote */
    CHECK(cn_transfer_verify_vote(&xfr, pk1, sig1) == SC_OK);
    CHECK(cn_transfer_verify_vote(&xfr, pk2, sig2) == SC_OK);

    /* Verify with wrong pubkey fails */
    CHECK(cn_transfer_verify_vote(&xfr, pk3, sig1) != SC_OK);

    /* Add vote 1 (quorum = 2) */
    int quorum = 2;
    bool reached = cn_transfer_add_vote(&xfr, pk1, sig1, quorum);
    CHECK(!reached);
    CHECK(xfr.cert_sig_count == 1);
    CHECK(xfr.state == CN_XFR_SOURCE_VERIFIED);

    /* Duplicate vote from pk1 should be ignored */
    reached = cn_transfer_add_vote(&xfr, pk1, sig1, quorum);
    CHECK(!reached);
    CHECK(xfr.cert_sig_count == 1);

    /* Add vote 2 -> quorum reached! */
    reached = cn_transfer_add_vote(&xfr, pk2, sig2, quorum);
    CHECK(reached);
    CHECK(xfr.cert_sig_count == 2);
    CHECK(xfr.state == CN_XFR_APPROVED);

    /* Advance to DESTINATION_SUBMITTED */
    CHECK(cn_transfer_transition(&xfr, CN_XFR_DESTINATION_SUBMITTED, "dest submitted") == SC_OK);
    CHECK(xfr.state == CN_XFR_DESTINATION_SUBMITTED);

    /* Advance to COMPLETED */
    CHECK(cn_transfer_transition(&xfr, CN_XFR_COMPLETED, "done") == SC_OK);
    CHECK(xfr.state == CN_XFR_COMPLETED);

    crypto_keypair_free(kp1);
    crypto_keypair_free(kp2);
    crypto_keypair_free(kp3);
}

int main(void)
{
    printf("test_cn_transfer:\n");
    RUN(test_transfer_arithmetic);
    RUN(test_transfer_state_machine_and_voting);
    return TEST_SUMMARY();
}
