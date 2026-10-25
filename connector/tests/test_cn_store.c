/* test_cn_store.c - Unit tests for persistent store. */
#define _POSIX_C_SOURCE 200809L

#include "testutil.h"
#include "cn_store.h"
#include "connector_types.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void cleanup_dir(const char *dir)
{
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", dir);
    if (system(cmd)) {}
}

static void test_store_activity_and_persistence(void)
{
    const char *test_dir = "/tmp/test_cn_store_act";
    cleanup_dir(test_dir);

    cn_store_t *store = NULL;
    CHECK(cn_store_open(&store, test_dir) == SC_OK);
    CHECK(store != NULL);
    CHECK(cn_store_activity_count(store) == 0);

    /* Create record 1 */
    cn_activity_record_t r1;
    memset(&r1, 0, sizeof(r1));
    memset(r1.record_id, 0x11, 32);
    r1.source_chain = CN_CHAIN_A;
    r1.amount = 1000;
    r1.status = CN_STATUS_VERIFIED;
    r1.observed_at = 12345;

    /* Create record 2 */
    cn_activity_record_t r2;
    memset(&r2, 0, sizeof(r2));
    memset(r2.record_id, 0x22, 32);
    r2.source_chain = CN_CHAIN_B;
    r2.amount = 2000;
    r2.status = CN_STATUS_FINALIZED;
    r2.observed_at = 12346;

    CHECK(cn_store_add_activity(store, &r1) == SC_OK);
    CHECK(cn_store_activity_count(store) == 1);

    /* Idempotent duplicate add */
    CHECK(cn_store_add_activity(store, &r1) == SC_OK);
    CHECK(cn_store_activity_count(store) == 1);

    CHECK(cn_store_add_activity(store, &r2) == SC_OK);
    CHECK(cn_store_activity_count(store) == 2);

    bool has = false;
    CHECK(cn_store_has_activity(store, r1.record_id, &has) == SC_OK && has == true);
    uint8_t unknown_id[32] = {0xFF};
    CHECK(cn_store_has_activity(store, unknown_id, &has) == SC_OK && has == false);

    cn_activity_record_t retrieved;
    CHECK(cn_store_get_activity_by_id(store, r1.record_id, &retrieved) == SC_OK);
    CHECK(retrieved.amount == 1000);
    CHECK(retrieved.status == CN_STATUS_VERIFIED);

    /* Test get_activity_since */
    cn_activity_record_t since_batch[10];
    size_t count = 0;
    CHECK(cn_store_get_activity_since(store, 0, since_batch, 10, &count) == SC_OK);
    CHECK(count == 2);

    CHECK(cn_store_get_activity_since(store, 1, since_batch, 10, &count) == SC_OK);
    CHECK(count == 1);
    CHECK(since_batch[0].amount == 2000);

    /* Close and reopen store */
    cn_store_close(store);
    store = NULL;

    CHECK(cn_store_open(&store, test_dir) == SC_OK);
    CHECK(cn_store_activity_count(store) == 2);

    CHECK(cn_store_has_activity(store, r1.record_id, &has) == SC_OK && has == true);
    CHECK(cn_store_has_activity(store, r2.record_id, &has) == SC_OK && has == true);

    cn_store_close(store);
    cleanup_dir(test_dir);
}

static void test_store_transfers_and_persistence(void)
{
    const char *test_dir = "/tmp/test_cn_store_xfr";
    cleanup_dir(test_dir);

    cn_store_t *store = NULL;
    CHECK(cn_store_open(&store, test_dir) == SC_OK);

    cn_transfer_t xfr;
    memset(&xfr, 0, sizeof(xfr));
    memset(xfr.transfer_id, 0xAB, 32);
    xfr.source_chain = CN_CHAIN_A;
    xfr.dest_chain = CN_CHAIN_B;
    xfr.source_amount = 500;
    xfr.dest_amount = 1000;
    xfr.state = CN_XFR_DETECTED;

    CHECK(cn_store_upsert_transfer(store, &xfr) == SC_OK);

    bool has = false;
    CHECK(cn_store_has_transfer(store, xfr.transfer_id, &has) == SC_OK && has == true);

    cn_transfer_t loaded;
    CHECK(cn_store_get_transfer(store, xfr.transfer_id, &loaded) == SC_OK);
    CHECK(loaded.source_amount == 500);
    CHECK(loaded.state == CN_XFR_DETECTED);

    /* Update transfer state and votes */
    xfr.state = CN_XFR_APPROVED;
    xfr.cert_sig_count = 2;
    memset(xfr.cert_signers[0], 0x11, 32);
    memset(xfr.cert_sigs[0], 0x22, 64);
    memset(xfr.cert_signers[1], 0x33, 32);
    memset(xfr.cert_sigs[1], 0x44, 64);
    snprintf(xfr.error_detail, sizeof(xfr.error_detail), "test approval");

    CHECK(cn_store_upsert_transfer(store, &xfr) == SC_OK);

    /* Test get_transfers_by_state */
    cn_transfer_t app_list[10];
    size_t count = 0;
    CHECK(cn_store_get_transfers_by_state(store, CN_XFR_APPROVED, app_list, 10, &count) == SC_OK);
    CHECK(count == 1);
    CHECK(app_list[0].cert_sig_count == 2);

    /* Close and reopen */
    cn_store_close(store);
    store = NULL;

    CHECK(cn_store_open(&store, test_dir) == SC_OK);
    memset(&loaded, 0, sizeof(loaded));
    CHECK(cn_store_get_transfer(store, xfr.transfer_id, &loaded) == SC_OK);
    CHECK(loaded.state == CN_XFR_APPROVED);
    CHECK(loaded.cert_sig_count == 2);
    CHECK(memcmp(loaded.cert_signers[0], xfr.cert_signers[0], 32) == 0);
    CHECK(strcmp(loaded.error_detail, "test approval") == 0);

    cn_store_close(store);
    cleanup_dir(test_dir);
}

static void test_store_seen_ids(void)
{
    const char *test_dir = "/tmp/test_cn_store_seen";
    cleanup_dir(test_dir);

    cn_store_t *store = NULL;
    CHECK(cn_store_open(&store, test_dir) == SC_OK);

    uint8_t id1[32] = {1, 2, 3};
    uint8_t id2[32] = {4, 5, 6};

    bool seen = false;
    CHECK(cn_store_is_seen(store, id1, &seen) == SC_OK && seen == false);

    CHECK(cn_store_mark_seen(store, id1) == SC_OK);
    CHECK(cn_store_is_seen(store, id1, &seen) == SC_OK && seen == true);
    CHECK(cn_store_is_seen(store, id2, &seen) == SC_OK && seen == false);

    /* Mark again (idempotent) */
    CHECK(cn_store_mark_seen(store, id1) == SC_OK);

    /* Close and reopen */
    cn_store_close(store);
    store = NULL;

    CHECK(cn_store_open(&store, test_dir) == SC_OK);
    CHECK(cn_store_is_seen(store, id1, &seen) == SC_OK && seen == true);
    CHECK(cn_store_is_seen(store, id2, &seen) == SC_OK && seen == false);

    cn_store_close(store);
    cleanup_dir(test_dir);
}

int main(void)
{
    printf("test_cn_store:\n");
    RUN(test_store_activity_and_persistence);
    RUN(test_store_transfers_and_persistence);
    RUN(test_store_seen_ids);
    return TEST_SUMMARY();
}
