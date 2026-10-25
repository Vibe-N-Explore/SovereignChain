/* test_cn_types.c - Unit tests for serialization and deserialization of connector types. */
#define _POSIX_C_SOURCE 200809L

#include "testutil.h"
#include "cn_activity.h"
#include "cn_rate.h"
#include "cn_transfer.h"
#include "connector_types.h"

#include <string.h>

static void test_activity_serialization_roundtrip(void)
{
    cn_activity_record_t orig;
    memset(&orig, 0, sizeof(orig));

    memset(orig.record_id, 0x11, 32);
    orig.source_chain = CN_CHAIN_A;
    memset(orig.tx_hash, 0x22, 32);
    memset(orig.sender, 0x33, 32);
    memset(orig.recipient, 0x44, 32);
    orig.amount = 12345678901234ULL;
    orig.fee = 5000ULL;
    orig.nonce = 42ULL;
    orig.tx_type = CN_TX_TYPE_CROSS_CHAIN;
    orig.source_round = 999ULL;
    memset(orig.source_vertex_hash, 0x55, 32);
    orig.status = CN_STATUS_FINALIZED;
    orig.observed_at = 1700000000LL;
    memset(orig.reporter_pubkey, 0x66, 32);
    memset(orig.reporter_sig, 0x77, 64);

    uint8_t buf[CN_ACTIVITY_WIRE_LEN];
    size_t written = 0;
    CHECK(cn_activity_serialize(&orig, buf, sizeof(buf), &written) == SC_OK);
    CHECK(written == CN_ACTIVITY_WIRE_LEN);

    cn_activity_record_t parsed;
    memset(&parsed, 0, sizeof(parsed));
    CHECK(cn_activity_deserialize(&parsed, buf, sizeof(buf)) == SC_OK);

    CHECK(memcmp(orig.record_id, parsed.record_id, 32) == 0);
    CHECK(orig.source_chain == parsed.source_chain);
    CHECK(memcmp(orig.tx_hash, parsed.tx_hash, 32) == 0);
    CHECK(memcmp(orig.sender, parsed.sender, 32) == 0);
    CHECK(memcmp(orig.recipient, parsed.recipient, 32) == 0);
    CHECK(orig.amount == parsed.amount);
    CHECK(orig.fee == parsed.fee);
    CHECK(orig.nonce == parsed.nonce);
    CHECK(orig.tx_type == parsed.tx_type);
    CHECK(orig.source_round == parsed.source_round);
    CHECK(memcmp(orig.source_vertex_hash, parsed.source_vertex_hash, 32) == 0);
    CHECK(orig.status == parsed.status);
    CHECK(orig.observed_at == parsed.observed_at);
    CHECK(memcmp(orig.reporter_pubkey, parsed.reporter_pubkey, 32) == 0);
    CHECK(memcmp(orig.reporter_sig, parsed.reporter_sig, 64) == 0);

    /* Test buffer too small */
    uint8_t small[CN_ACTIVITY_WIRE_LEN - 1];
    CHECK(cn_activity_serialize(&orig, small, sizeof(small), &written) == SC_ERR_INVALID);
    CHECK(cn_activity_deserialize(&parsed, small, sizeof(small)) == SC_ERR_INVALID);
}

static void test_rate_serialization_roundtrip(void)
{
    cn_rate_t orig;
    memset(&orig, 0, sizeof(orig));
    orig.rate_num = 3;
    orig.rate_den = 2;
    orig.version = 7;
    orig.updated_at = 1711122233LL;
    memset(orig.updater_pubkey, 0x88, 32);
    memset(orig.updater_sig, 0x99, 64);

    uint8_t buf[CN_RATE_WIRE_LEN];
    size_t written = 0;
    CHECK(cn_rate_serialize(&orig, buf, sizeof(buf), &written) == SC_OK);
    CHECK(written == CN_RATE_WIRE_LEN);

    cn_rate_t parsed;
    memset(&parsed, 0, sizeof(parsed));
    CHECK(cn_rate_deserialize(&parsed, buf, sizeof(buf)) == SC_OK);

    CHECK(orig.rate_num == parsed.rate_num);
    CHECK(orig.rate_den == parsed.rate_den);
    CHECK(orig.version == parsed.version);
    CHECK(orig.updated_at == parsed.updated_at);
    CHECK(memcmp(orig.updater_pubkey, parsed.updater_pubkey, 32) == 0);
    CHECK(memcmp(orig.updater_sig, parsed.updater_sig, 64) == 0);

    /* Test short buffer */
    CHECK(cn_rate_serialize(&orig, buf, CN_RATE_WIRE_LEN - 1, &written) == SC_ERR_INVALID);
    CHECK(cn_rate_deserialize(&parsed, buf, CN_RATE_WIRE_LEN - 1) == SC_ERR_INVALID);
}

static void test_transfer_serialization_roundtrip(void)
{
    cn_transfer_t orig;
    memset(&orig, 0, sizeof(orig));
    memset(orig.transfer_id, 0xAA, 32);
    orig.source_chain = CN_CHAIN_A;
    orig.dest_chain = CN_CHAIN_B;
    memset(orig.source_tx_hash, 0xBB, 32);
    memset(orig.sender, 0xCC, 32);
    memset(orig.recipient, 0xDD, 32);
    orig.source_amount = 500000;
    orig.dest_amount = 750000;
    orig.rate_num = 3;
    orig.rate_den = 2;
    orig.rate_version = 4;
    orig.state = CN_XFR_APPROVED;
    orig.initiated_at = 1705000000LL;
    orig.last_updated_at = 1705000010LL;

    uint8_t buf[CN_TRANSFER_CORE_WIRE_LEN];
    size_t written = 0;
    CHECK(cn_transfer_serialize(&orig, buf, sizeof(buf), &written) == SC_OK);
    CHECK(written == CN_TRANSFER_CORE_WIRE_LEN);

    cn_transfer_t parsed;
    memset(&parsed, 0, sizeof(parsed));
    CHECK(cn_transfer_deserialize(&parsed, buf, sizeof(buf)) == SC_OK);

    CHECK(memcmp(orig.transfer_id, parsed.transfer_id, 32) == 0);
    CHECK(orig.source_chain == parsed.source_chain);
    CHECK(orig.dest_chain == parsed.dest_chain);
    CHECK(memcmp(orig.source_tx_hash, parsed.source_tx_hash, 32) == 0);
    CHECK(memcmp(orig.sender, parsed.sender, 32) == 0);
    CHECK(memcmp(orig.recipient, parsed.recipient, 32) == 0);
    CHECK(orig.source_amount == parsed.source_amount);
    CHECK(orig.dest_amount == parsed.dest_amount);
    CHECK(orig.rate_num == parsed.rate_num);
    CHECK(orig.rate_den == parsed.rate_den);
    CHECK(orig.rate_version == parsed.rate_version);
    CHECK(orig.state == parsed.state);
    CHECK(orig.initiated_at == parsed.initiated_at);
    CHECK(orig.last_updated_at == parsed.last_updated_at);
}

int main(void)
{
    printf("test_cn_types:\n");
    RUN(test_activity_serialization_roundtrip);
    RUN(test_rate_serialization_roundtrip);
    RUN(test_transfer_serialization_roundtrip);
    return TEST_SUMMARY();
}
