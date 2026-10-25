/* cn_rate.c - Exchange rate implementation. */
#define _POSIX_C_SOURCE 200809L

#include "cn_rate.h"
#include "cn_config.h"

#include <string.h>
#include <time.h>

#include "../../src/crypto.h"
#include "../../src/err.h"

static const uint8_t RATE_DOMAIN[7] = {'R', 'A', 'T', 'E', '/', 'v', '1'};

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

static void compute_rate_hash(const cn_rate_t *rate, uint8_t hash_out[SC_SHA256_LEN])
{
    /* domain(7) || rate_num(8 BE) || rate_den(8 BE) || version(8 BE) = 31 bytes */
    uint8_t buf[7 + 8 + 8 + 8];
    memcpy(buf, RATE_DOMAIN, 7);
    pack_u64_be(buf + 7, rate->rate_num);
    pack_u64_be(buf + 15, rate->rate_den);
    pack_u64_be(buf + 23, rate->version);
    crypto_sha256(buf, sizeof(buf), hash_out);
}

sc_err_t cn_rate_sign(cn_rate_t *rate, const sc_keypair_t *my_kp)
{
    if (!rate || !my_kp)
        return SC_ERR_INVALID;

    if (rate->rate_den == 0)
        return SC_ERR_INVALID;

    if (crypto_get_pubkey(my_kp, rate->updater_pubkey) != SC_OK)
        return SC_ERR_IO;

    rate->updated_at = (int64_t)time(NULL);

    uint8_t hash[SC_SHA256_LEN];
    compute_rate_hash(rate, hash);

    if (crypto_sign(my_kp, hash, sizeof(hash), rate->updater_sig) != SC_OK)
        return SC_ERR_IO;

    return SC_OK;
}

sc_err_t cn_rate_verify(const cn_rate_t *rate)
{
    if (!rate)
        return SC_ERR_INVALID;

    if (rate->rate_den == 0)
        return SC_ERR_INVALID;

    sc_keypair_t *pub_kp = NULL;
    if (crypto_pubkey_from_raw(&pub_kp, rate->updater_pubkey) != SC_OK)
        return SC_ERR_INVALID;

    uint8_t hash[SC_SHA256_LEN];
    compute_rate_hash(rate, hash);

    sc_err_t rc = crypto_verify(pub_kp, hash, sizeof(hash), rate->updater_sig);
    crypto_keypair_free(pub_kp);
    return rc;
}

sc_err_t cn_rate_validate(const cn_rate_t *rate)
{
    if (!rate)
        return SC_ERR_INVALID;

    if (rate->rate_den == 0 || rate->rate_num == 0)
        return SC_ERR_INVALID;

    /* Prevent overflow in typical cross-chain arithmetic:
     * Check if rate_num / rate_den is ridiculously huge (> 1,000,000x) */
    if (rate->rate_num / rate->rate_den > 1000000ULL)
        return SC_ERR_INVALID;

    return SC_OK;
}

sc_err_t cn_rate_serialize(const cn_rate_t *rate, uint8_t *buf, size_t buflen, size_t *written)
{
    if (!rate || !buf || buflen < CN_RATE_WIRE_LEN)
        return SC_ERR_INVALID;

    pack_u64_be(buf, rate->rate_num);
    pack_u64_be(buf + 8, rate->rate_den);
    pack_u64_be(buf + 16, rate->version);
    pack_i64_be(buf + 24, rate->updated_at);
    memcpy(buf + 32, rate->updater_pubkey, SC_ED25519_PUBKEY_LEN);
    memcpy(buf + 64, rate->updater_sig, SC_ED25519_SIG_LEN);

    if (written)
        *written = CN_RATE_WIRE_LEN;

    return SC_OK;
}

sc_err_t cn_rate_deserialize(cn_rate_t *rate, const uint8_t *buf, size_t len)
{
    if (!rate || !buf || len < CN_RATE_WIRE_LEN)
        return SC_ERR_INVALID;

    rate->rate_num = unpack_u64_be(buf);
    rate->rate_den = unpack_u64_be(buf + 8);
    rate->version = unpack_u64_be(buf + 16);
    rate->updated_at = unpack_i64_be(buf + 24);
    memcpy(rate->updater_pubkey, buf + 32, SC_ED25519_PUBKEY_LEN);
    memcpy(rate->updater_sig, buf + 64, SC_ED25519_SIG_LEN);

    return SC_OK;
}

sc_err_t cn_rate_save(const cn_rate_t *a_to_b, const cn_rate_t *b_to_a, const char *data_dir)
{
    char errbuf[128];
    return cn_config_save_rate(a_to_b, b_to_a, data_dir, errbuf, sizeof(errbuf));
}

sc_err_t cn_rate_load(cn_rate_t *a_to_b, cn_rate_t *b_to_a, const char *data_dir)
{
    char errbuf[128];
    return cn_config_load_rate(a_to_b, b_to_a, data_dir, errbuf, sizeof(errbuf));
}
