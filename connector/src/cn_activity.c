/* cn_activity.c - Activity record creation, signing, serialization, and verification. */
#define _POSIX_C_SOURCE 200809L

#include "cn_activity.h"

#include <string.h>
#include <time.h>

#include "../../src/crypto.h"
#include "../../src/err.h"

static const uint8_t ACTIVITY_DOMAIN[11] = {'A', 'C', 'T', 'I', 'V', 'I', 'T', 'Y', '/', 'v', '1'};
static const uint8_t REPORT_DOMAIN[18]   = {'A', 'C', 'T', 'I', 'V', 'I', 'T', 'Y', '_', 'R', 'E', 'P', 'O', 'R', 'T', '/', 'v', '1'};

static void pack_u64_be(uint8_t *dest, uint64_t val)
{
    for (int i = 7; i >= 0; i--) {
        dest[i] = (uint8_t)(val & 0xFF);
        val >>= 8;
    }
}

static uint64_t unpack_u64_be(const uint8_t *src)
{
    uint64_t val = 0;
    for (int i = 0; i < 8; i++) {
        val = (val << 8) | src[i];
    }
    return val;
}

static void pack_i64_be(uint8_t *dest, int64_t val)
{
    pack_u64_be(dest, (uint64_t)val);
}

static int64_t unpack_i64_be(const uint8_t *src)
{
    return (int64_t)unpack_u64_be(src);
}

sc_err_t cn_activity_compute_id(uint8_t source_chain, const uint8_t tx_hash[32],
                                 uint8_t record_id_out[32])
{
    if (!tx_hash || !record_id_out)
        return SC_ERR_INVALID;

    /* Domain: "ACTIVITY/v1"(11) || source_chain(1) || tx_hash(32) = 44 bytes */
    uint8_t buf[11 + 1 + SC_SHA256_LEN];
    memcpy(buf, ACTIVITY_DOMAIN, 11);
    buf[11] = source_chain;
    memcpy(buf + 12, tx_hash, SC_SHA256_LEN);

    return crypto_sha256(buf, sizeof(buf), record_id_out);
}

static void compute_report_hash(const uint8_t record_id[32], uint8_t source_chain,
                                const uint8_t tx_hash[32], uint8_t status,
                                int64_t observed_at, uint8_t hash_out[32])
{
    /* "ACTIVITY_REPORT/v1"(18) || record_id(32) || source_chain(1) || tx_hash(32) || status(1) || observed_at(8 BE) = 92 bytes */
    uint8_t buf[18 + 32 + 1 + 32 + 1 + 8];
    memcpy(buf, REPORT_DOMAIN, 18);
    memcpy(buf + 18, record_id, 32);
    buf[50] = source_chain;
    memcpy(buf + 51, tx_hash, 32);
    buf[83] = status;
    pack_i64_be(buf + 84, observed_at);

    crypto_sha256(buf, sizeof(buf), hash_out);
}

sc_err_t cn_activity_create(cn_activity_record_t *rec, uint8_t source_chain,
                             const sc_tx_t *tx, uint64_t source_round,
                             const uint8_t source_vertex_hash[32],
                             cn_activity_status_t status,
                             const sc_keypair_t *my_kp)
{
    if (!rec || !tx || !my_kp)
        return SC_ERR_INVALID;

    memset(rec, 0, sizeof(*rec));
    rec->source_chain = source_chain;
    memcpy(rec->tx_hash, tx->hash, SC_SHA256_LEN);
    memcpy(rec->sender, tx->sender, SC_ED25519_PUBKEY_LEN);
    memcpy(rec->recipient, tx->recipient, SC_ED25519_PUBKEY_LEN);
    rec->amount = tx->amount;
    rec->fee = tx->fee;
    rec->nonce = tx->nonce;
    rec->tx_type = CN_TX_TYPE_SAME_CHAIN;
    rec->source_round = source_round;
    if (source_vertex_hash) {
        memcpy(rec->source_vertex_hash, source_vertex_hash, SC_SHA256_LEN);
    }
    rec->status = (uint8_t)status;
    rec->observed_at = (int64_t)time(NULL);

    if (cn_activity_compute_id(source_chain, tx->hash, rec->record_id) != SC_OK)
        return SC_ERR_IO;

    if (crypto_get_pubkey(my_kp, rec->reporter_pubkey) != SC_OK)
        return SC_ERR_IO;

    uint8_t rep_hash[SC_SHA256_LEN];
    compute_report_hash(rec->record_id, rec->source_chain, rec->tx_hash,
                        rec->status, rec->observed_at, rep_hash);

    if (crypto_sign(my_kp, rep_hash, sizeof(rep_hash), rec->reporter_sig) != SC_OK)
        return SC_ERR_IO;

    return SC_OK;
}

sc_err_t cn_activity_verify(const cn_activity_record_t *rec)
{
    if (!rec)
        return SC_ERR_INVALID;

    /* Verify record_id consistency */
    uint8_t expected_id[SC_SHA256_LEN];
    if (cn_activity_compute_id(rec->source_chain, rec->tx_hash, expected_id) != SC_OK)
        return SC_ERR_INVALID;

    if (memcmp(rec->record_id, expected_id, SC_SHA256_LEN) != 0)
        return SC_ERR_INVALID;

    /* Verify reporter signature */
    sc_keypair_t *pub_kp = NULL;
    if (crypto_pubkey_from_raw(&pub_kp, rec->reporter_pubkey) != SC_OK)
        return SC_ERR_INVALID;

    uint8_t rep_hash[SC_SHA256_LEN];
    compute_report_hash(rec->record_id, rec->source_chain, rec->tx_hash,
                        rec->status, rec->observed_at, rep_hash);

    sc_err_t rc = crypto_verify(pub_kp, rep_hash, sizeof(rep_hash), rec->reporter_sig);
    crypto_keypair_free(pub_kp);
    return rc;
}

sc_err_t cn_activity_serialize(const cn_activity_record_t *rec, uint8_t *buf, size_t buflen, size_t *written)
{
    if (!rec || !buf || buflen < CN_ACTIVITY_WIRE_LEN)
        return SC_ERR_INVALID;

    uint8_t *p = buf;

    memcpy(p, rec->record_id, 32);                 p += 32;
    *p = rec->source_chain;                         p += 1;
    memcpy(p, rec->tx_hash, 32);                   p += 32;
    memcpy(p, rec->sender, 32);                    p += 32;
    memcpy(p, rec->recipient, 32);                 p += 32;
    pack_u64_be(p, rec->amount);                   p += 8;
    pack_u64_be(p, rec->fee);                      p += 8;
    pack_u64_be(p, rec->nonce);                    p += 8;
    *p = rec->tx_type;                             p += 1;
    pack_u64_be(p, rec->source_round);             p += 8;
    memcpy(p, rec->source_vertex_hash, 32);        p += 32;
    *p = rec->status;                              p += 1;
    pack_i64_be(p, rec->observed_at);              p += 8;
    memcpy(p, rec->reporter_pubkey, 32);           p += 32;
    memcpy(p, rec->reporter_sig, 64);              p += 64;

    if (written)
        *written = (size_t)(p - buf);

    return SC_OK;
}

sc_err_t cn_activity_deserialize(cn_activity_record_t *rec, const uint8_t *buf, size_t len)
{
    if (!rec || !buf || len < CN_ACTIVITY_WIRE_LEN)
        return SC_ERR_INVALID;

    const uint8_t *p = buf;

    memcpy(rec->record_id, p, 32);                 p += 32;
    rec->source_chain = *p;                         p += 1;
    memcpy(rec->tx_hash, p, 32);                   p += 32;
    memcpy(rec->sender, p, 32);                    p += 32;
    memcpy(rec->recipient, p, 32);                 p += 32;
    rec->amount = unpack_u64_be(p);                p += 8;
    rec->fee = unpack_u64_be(p);                   p += 8;
    rec->nonce = unpack_u64_be(p);                 p += 8;
    rec->tx_type = *p;                             p += 1;
    rec->source_round = unpack_u64_be(p);          p += 8;
    memcpy(rec->source_vertex_hash, p, 32);        p += 32;
    rec->status = *p;                              p += 1;
    rec->observed_at = unpack_i64_be(p);           p += 8;
    memcpy(rec->reporter_pubkey, p, 32);           p += 32;
    memcpy(rec->reporter_sig, p, 64);              p += 64;

    return SC_OK;
}
