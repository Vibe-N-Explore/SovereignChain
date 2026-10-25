/* tx.c - Transaction creation, serialization, signing, and verification. */
#define _POSIX_C_SOURCE 200809L

#include "tx.h"

#include <string.h>

static void pack_u64_be(uint8_t *dest, uint64_t val)
{
    dest[0] = (uint8_t)(val >> 56);
    dest[1] = (uint8_t)(val >> 48);
    dest[2] = (uint8_t)(val >> 40);
    dest[3] = (uint8_t)(val >> 32);
    dest[4] = (uint8_t)(val >> 24);
    dest[5] = (uint8_t)(val >> 16);
    dest[6] = (uint8_t)(val >> 8);
    dest[7] = (uint8_t)(val);
}

static uint64_t unpack_u64_be(const uint8_t *src)
{
    return ((uint64_t)src[0] << 56) |
           ((uint64_t)src[1] << 48) |
           ((uint64_t)src[2] << 40) |
           ((uint64_t)src[3] << 32) |
           ((uint64_t)src[4] << 24) |
           ((uint64_t)src[5] << 16) |
           ((uint64_t)src[6] << 8)  |
           ((uint64_t)src[7]);
}

void tx_get_signing_bytes(const sc_tx_t *tx, uint8_t out[SC_TX_PAYLOAD_LEN])
{
    static const uint8_t domain[5] = {'T', 'X', '/', 'v', '1'};
    memcpy(out, domain, 5);
    memcpy(out + 5, tx->sender, SC_ED25519_PUBKEY_LEN);
    memcpy(out + 5 + SC_ED25519_PUBKEY_LEN, tx->recipient, SC_ED25519_PUBKEY_LEN);
    pack_u64_be(out + 5 + 2 * SC_ED25519_PUBKEY_LEN, tx->amount);
    pack_u64_be(out + 5 + 2 * SC_ED25519_PUBKEY_LEN + 8, tx->fee);
    pack_u64_be(out + 5 + 2 * SC_ED25519_PUBKEY_LEN + 16, tx->nonce);
}

sc_err_t tx_compute_hash(const sc_tx_t *tx, uint8_t hash_out[SC_SHA256_LEN])
{
    if (!tx || !hash_out)
        return SC_ERR_INVALID;

    uint8_t signing_bytes[SC_TX_PAYLOAD_LEN];
    tx_get_signing_bytes(tx, signing_bytes);
    return crypto_sha256(signing_bytes, sizeof(signing_bytes), hash_out);
}

sc_err_t tx_create(sc_tx_t *tx, const sc_keypair_t *sender_kp,
                   const uint8_t recipient[SC_ED25519_PUBKEY_LEN],
                   uint64_t amount, uint64_t fee, uint64_t nonce)
{
    if (!tx || !sender_kp || !recipient)
        return SC_ERR_INVALID;

    memset(tx, 0, sizeof(*tx));
    if (crypto_get_pubkey(sender_kp, tx->sender) != SC_OK)
        return SC_ERR_IO;

    memcpy(tx->recipient, recipient, SC_ED25519_PUBKEY_LEN);
    tx->amount = amount;
    tx->fee    = fee;
    tx->nonce  = nonce;

    uint8_t signing_bytes[SC_TX_PAYLOAD_LEN];
    tx_get_signing_bytes(tx, signing_bytes);

    if (crypto_sign(sender_kp, signing_bytes, sizeof(signing_bytes), tx->sig) != SC_OK)
        return SC_ERR_IO;

    return crypto_sha256(signing_bytes, sizeof(signing_bytes), tx->hash);
}

sc_err_t tx_verify_sig(const sc_tx_t *tx)
{
    if (!tx)
        return SC_ERR_INVALID;

    sc_keypair_t *pub_handle = NULL;
    sc_err_t rc = crypto_pubkey_from_raw(&pub_handle, tx->sender);
    if (rc != SC_OK)
        return rc;

    uint8_t signing_bytes[SC_TX_PAYLOAD_LEN];
    tx_get_signing_bytes(tx, signing_bytes);

    rc = crypto_verify(pub_handle, signing_bytes, sizeof(signing_bytes), tx->sig);
    crypto_keypair_free(pub_handle);
    return rc;
}

sc_err_t tx_serialize(const sc_tx_t *tx, uint8_t *buf, size_t buflen, size_t *written_out)
{
    if (!tx || !buf || buflen < SC_TX_WIRE_LEN)
        return SC_ERR_INVALID;

    memcpy(buf, tx->sender, SC_ED25519_PUBKEY_LEN);
    memcpy(buf + 32, tx->recipient, SC_ED25519_PUBKEY_LEN);
    pack_u64_be(buf + 64, tx->amount);
    pack_u64_be(buf + 72, tx->fee);
    pack_u64_be(buf + 80, tx->nonce);
    memcpy(buf + 88, tx->sig, SC_ED25519_SIG_LEN);

    if (written_out)
        *written_out = SC_TX_WIRE_LEN;
    return SC_OK;
}

sc_err_t tx_deserialize(sc_tx_t *tx, const uint8_t *buf, size_t buflen)
{
    if (!tx || !buf || buflen < SC_TX_WIRE_LEN)
        return SC_ERR_INVALID;

    memset(tx, 0, sizeof(*tx));
    memcpy(tx->sender, buf, SC_ED25519_PUBKEY_LEN);
    memcpy(tx->recipient, buf + 32, SC_ED25519_PUBKEY_LEN);
    tx->amount = unpack_u64_be(buf + 64);
    tx->fee    = unpack_u64_be(buf + 72);
    tx->nonce  = unpack_u64_be(buf + 80);
    memcpy(tx->sig, buf + 88, SC_ED25519_SIG_LEN);

    return tx_compute_hash(tx, tx->hash);
}
