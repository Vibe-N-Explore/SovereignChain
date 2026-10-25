/* cn_transfer.c - SovereignChain cross-chain transfer coordination engine. */
#define _POSIX_C_SOURCE 200809L

#include "cn_transfer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cn_activity.h"
#include "cn_chain.h"
#include "cn_rate.h"
#include "cn_store.h"
#include "../../src/crypto.h"
#include "../../src/log.h"

sc_err_t cn_transfer_compute_id(uint8_t source_chain, const uint8_t source_tx_hash[32],
                                 uint8_t transfer_id_out[32])
{
    if (!source_tx_hash || !transfer_id_out)
        return SC_ERR_INVALID;

    static const uint8_t domain[7] = {'X','F','E','R','/','v','1'};
    uint8_t buf[7 + 1 + 32];
    memcpy(buf, domain, 7);
    buf[7] = source_chain;
    memcpy(buf + 8, source_tx_hash, 32);

    return crypto_sha256(buf, sizeof(buf), transfer_id_out);
}

sc_err_t cn_transfer_calc_dest_amount(uint64_t source_amount, 
                                       uint64_t rate_num, uint64_t rate_den,
                                       uint64_t *dest_amount_out)
{
    if (!dest_amount_out || rate_den == 0)
        return SC_ERR_INVALID;

    __uint128_t prod = (__uint128_t)source_amount * rate_num;
    *dest_amount_out = (uint64_t)(prod / rate_den);
    return SC_OK;
}

sc_err_t cn_transfer_create(cn_transfer_t *xfr, uint8_t source_chain,
                             const sc_tx_t *source_tx,
                             const cn_rate_t *applicable_rate)
{
    if (!xfr || !source_tx)
        return SC_ERR_INVALID;

    memset(xfr, 0, sizeof(*xfr));
    xfr->source_chain = source_chain;
    xfr->dest_chain = (source_chain == CN_CHAIN_A) ? CN_CHAIN_B : CN_CHAIN_A;
    memcpy(xfr->source_tx_hash, source_tx->hash, 32);
    memcpy(xfr->sender, source_tx->sender, SC_ED25519_PUBKEY_LEN);
    memcpy(xfr->recipient, source_tx->recipient, SC_ED25519_PUBKEY_LEN);
    
    if (cn_transfer_compute_id(source_chain, source_tx->hash, xfr->transfer_id) != SC_OK)
        return SC_ERR_IO;

    xfr->source_amount = source_tx->amount;
    
    uint64_t num = 1, den = 1;
    if (applicable_rate) {
        num = applicable_rate->rate_num;
        den = applicable_rate->rate_den;
        xfr->rate_version = applicable_rate->version;
    }
    xfr->rate_num = num;
    xfr->rate_den = den;

    if (cn_transfer_calc_dest_amount(xfr->source_amount, num, den, &xfr->dest_amount) != SC_OK)
        return SC_ERR_IO;

    xfr->state = CN_XFR_DETECTED;
    return SC_OK;
}

sc_err_t cn_transfer_sign_vote(const cn_transfer_t *xfr, const sc_keypair_t *my_kp,
                                uint8_t sig_out[SC_ED25519_SIG_LEN])
{
    if (!xfr || !my_kp || !sig_out)
        return SC_ERR_INVALID;

    static const uint8_t domain[13] = {'X','F','E','R','_','V','O','T','E','/','v','1'};
    uint8_t buf[13 + 32 + 8 + 8];
    memcpy(buf, domain, 13);
    memcpy(buf + 13, xfr->transfer_id, 32);
    
    buf[45] = (uint8_t)(xfr->dest_amount >> 56);
    buf[46] = (uint8_t)(xfr->dest_amount >> 48);
    buf[47] = (uint8_t)(xfr->dest_amount >> 40);
    buf[48] = (uint8_t)(xfr->dest_amount >> 32);
    buf[49] = (uint8_t)(xfr->dest_amount >> 24);
    buf[50] = (uint8_t)(xfr->dest_amount >> 16);
    buf[51] = (uint8_t)(xfr->dest_amount >> 8);
    buf[52] = (uint8_t)(xfr->dest_amount);

    buf[53] = (uint8_t)(xfr->rate_version >> 56);
    buf[54] = (uint8_t)(xfr->rate_version >> 48);
    buf[55] = (uint8_t)(xfr->rate_version >> 40);
    buf[56] = (uint8_t)(xfr->rate_version >> 32);
    buf[57] = (uint8_t)(xfr->rate_version >> 24);
    buf[58] = (uint8_t)(xfr->rate_version >> 16);
    buf[59] = (uint8_t)(xfr->rate_version >> 8);
    buf[60] = (uint8_t)(xfr->rate_version);

    uint8_t digest[32];
    crypto_sha256(buf, sizeof(buf), digest);

    return crypto_sign(my_kp, digest, 32, sig_out);
}

sc_err_t cn_transfer_verify_vote(const cn_transfer_t *xfr,
                                  const uint8_t voter_pubkey[32],
                                  const uint8_t sig[64])
{
    if (!xfr || !voter_pubkey || !sig)
        return SC_ERR_INVALID;

    static const uint8_t domain[13] = {'X','F','E','R','_','V','O','T','E','/','v','1'};
    uint8_t buf[13 + 32 + 8 + 8];
    memcpy(buf, domain, 13);
    memcpy(buf + 13, xfr->transfer_id, 32);
    
    buf[45] = (uint8_t)(xfr->dest_amount >> 56);
    buf[46] = (uint8_t)(xfr->dest_amount >> 48);
    buf[47] = (uint8_t)(xfr->dest_amount >> 40);
    buf[48] = (uint8_t)(xfr->dest_amount >> 32);
    buf[49] = (uint8_t)(xfr->dest_amount >> 24);
    buf[50] = (uint8_t)(xfr->dest_amount >> 16);
    buf[51] = (uint8_t)(xfr->dest_amount >> 8);
    buf[52] = (uint8_t)(xfr->dest_amount);

    buf[53] = (uint8_t)(xfr->rate_version >> 56);
    buf[54] = (uint8_t)(xfr->rate_version >> 48);
    buf[55] = (uint8_t)(xfr->rate_version >> 40);
    buf[56] = (uint8_t)(xfr->rate_version >> 32);
    buf[57] = (uint8_t)(xfr->rate_version >> 24);
    buf[58] = (uint8_t)(xfr->rate_version >> 16);
    buf[59] = (uint8_t)(xfr->rate_version >> 8);
    buf[60] = (uint8_t)(xfr->rate_version);

    uint8_t digest[32];
    crypto_sha256(buf, sizeof(buf), digest);

    sc_keypair_t *pub_handle = NULL;
    if (crypto_pubkey_from_raw(&pub_handle, voter_pubkey) != SC_OK)
        return SC_ERR_IO;

    sc_err_t rc = crypto_verify(pub_handle, digest, 32, sig);
    crypto_keypair_free(pub_handle);
    return rc;
}

bool cn_transfer_add_vote(cn_transfer_t *xfr, const uint8_t voter_pubkey[32],
                           const uint8_t sig[64], int quorum)
{
    if (!xfr || !voter_pubkey || !sig || quorum <= 0)
        return false;

    if (cn_transfer_verify_vote(xfr, voter_pubkey, sig) != SC_OK)
        return false;

    size_t target_quorum = (size_t)quorum;

    /* Check duplicate vote using aliases defined in connector_types.h */
    for (size_t i = 0; i < xfr->cert_sig_count; i++) {
        if (memcmp(xfr->cert_signers[i], voter_pubkey, 32) == 0) {
            return (xfr->cert_sig_count >= target_quorum);
        }
    }

    if (xfr->cert_sig_count < CN_MAX_PEERS) {
        memcpy(xfr->cert_signers[xfr->cert_sig_count], voter_pubkey, 32);
        memcpy(xfr->cert_sigs[xfr->cert_sig_count], sig, 64);
        xfr->cert_sig_count++;
    }

    return (xfr->cert_sig_count >= target_quorum);
}

sc_err_t cn_transfer_transition(cn_transfer_t *xfr, cn_transfer_state_t new_state,
                                 const char *detail)
{
    if (!xfr)
        return SC_ERR_INVALID;
    xfr->state = new_state;
    if (detail) {
        snprintf(xfr->error_detail, sizeof(xfr->error_detail), "%s", detail);
    }
    return SC_OK;
}

sc_err_t cn_transfer_serialize(const cn_transfer_t *xfr, uint8_t *buf, size_t buflen, size_t *written)
{
    if (!xfr || !buf || buflen < sizeof(cn_transfer_t))
        return SC_ERR_INVALID;
    memcpy(buf, xfr, sizeof(cn_transfer_t));
    if (written)
        *written = sizeof(cn_transfer_t);
    return SC_OK;
}

sc_err_t cn_transfer_deserialize(cn_transfer_t *xfr, const uint8_t *buf, size_t len)
{
    if (!xfr || !buf || len < sizeof(cn_transfer_t))
        return SC_ERR_INVALID;
    memcpy(xfr, buf, sizeof(cn_transfer_t));
    return SC_OK;
}