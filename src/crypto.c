/* crypto.c - Ed25519 and SHA-256 via OpenSSL EVP.
 *
 * OpenSSL's EVP API wraps different algorithms behind a uniform interface.
 * Key types we use:
 *   EVP_PKEY     - Generic "private/public key" container (opaque handle)
 *   EVP_MD_CTX   - Message Digest context (signing, verification, hashing)
 *   EVP_PKEY_CTX - Key generation context
 *
 * Ed25519 in EVP is special: it signs in a single step (EVP_DigestSign)
 * rather than the usual Init/Update/Final sequence, because Ed25519
 * has its own internal hash (SHA-512) built into the algorithm.
 */
#define _POSIX_C_SOURCE 200809L
#include "crypto.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

/* ------------------------------------------------------------------ */
/* The opaque struct: defined here, invisible to callers               */
/* ------------------------------------------------------------------ */

struct sc_keypair {
    EVP_PKEY *pkey;     /* OpenSSL's generic key handle                */
    bool      has_priv; /* true = has private key material (can sign)  */
};

/* ------------------------------------------------------------------ */
/* Key Generation                                                      */
/* ------------------------------------------------------------------ */

sc_err_t crypto_keygen(sc_keypair_t **kp_out)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    sc_keypair_t *kp;

    if (!kp_out)
        return SC_ERR_INVALID;

    /* EVP_PKEY_CTX_new_id creates a key-generation context for a specific
     * algorithm identified by its NID (Numeric ID). EVP_PKEY_ED25519 is
     * the NID for Ed25519. The NULL engine means "use default provider." */
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    if (!ctx)
        return SC_ERR_IO;

    if (EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return SC_ERR_IO;
    }
    EVP_PKEY_CTX_free(ctx);

    kp = calloc(1, sizeof(*kp));
    if (!kp) {
        EVP_PKEY_free(pkey);
        return SC_ERR_IO;
    }
    kp->pkey = pkey;
    kp->has_priv = true;

    *kp_out = kp;
    return SC_OK;
}

/* ------------------------------------------------------------------ */
/* Key I/O                                                             */
/* ------------------------------------------------------------------ */

sc_err_t crypto_save_privkey(const sc_keypair_t *kp, const char *path)
{
    FILE *f;

    if (!kp || !kp->pkey || !kp->has_priv || !path)
        return SC_ERR_INVALID;

    f = fopen(path, "w");
    if (!f)
        return SC_ERR_IO;

    /* Set file permissions to 0600 (owner read+write only) BEFORE writing.
     * S_IRUSR | S_IWUSR are POSIX permission constants.
     * This prevents other OS users from reading the private key file.
     * On a multi-user system, this is critical. */
    if (chmod(path, S_IRUSR | S_IWUSR) != 0) {
        fclose(f);
        return SC_ERR_IO;
    }

    /* PEM_write_PrivateKey serializes the key to PEM format:
     *   -----BEGIN PRIVATE KEY-----
     *   <base64-encoded DER key material>
     *   -----END PRIVATE KEY-----
     * The NULL arguments mean: no encryption cipher, no passphrase.
     * In production, you'd encrypt the PEM with a passphrase. */
    if (!PEM_write_PrivateKey(f, kp->pkey, NULL, NULL, 0, NULL, NULL)) {
        fclose(f);
        return SC_ERR_IO;
    }
    fclose(f);
    return SC_OK;
}

sc_err_t crypto_load_privkey(sc_keypair_t **kp_out, const char *path,
                             char *errbuf, size_t errlen)
{
    FILE *f;
    EVP_PKEY *pkey;
    sc_keypair_t *kp;

    if (!kp_out || !path)
        return SC_ERR_INVALID;

    f = fopen(path, "r");
    if (!f) {
        if (errbuf)
            snprintf(errbuf, errlen, "cannot open key file %s: %s",
                     path, strerror(errno));
        return SC_ERR_IO;
    }

    /* PEM_read_PrivateKey parses a PEM-encoded private key. The NULLs:
     *   arg2: no pre-existing EVP_PKEY to reuse (allocates fresh)
     *   arg3: no password callback function
     *   arg4: no passphrase string
     * Returns NULL if the file isn't a valid PEM key. */
    pkey = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);
    if (!pkey) {
        if (errbuf)
            snprintf(errbuf, errlen, "%s: not a valid PEM private key", path);
        return SC_ERR_PARSE;
    }

    /* Verify it's Ed25519 and not RSA/ECDSA/etc.
     * EVP_PKEY_id() returns the algorithm NID. In OpenSSL 3.x this is
     * soft-deprecated in favor of EVP_PKEY_get_id(), but it works in
     * both 1.1.x and 3.x. */
    if (EVP_PKEY_id(pkey) != EVP_PKEY_ED25519) {
        if (errbuf)
            snprintf(errbuf, errlen, "%s: not an Ed25519 key (type=%d)",
                     path, EVP_PKEY_id(pkey));
        EVP_PKEY_free(pkey);
        return SC_ERR_INVALID;
    }

    kp = calloc(1, sizeof(*kp));
    if (!kp) {
        EVP_PKEY_free(pkey);
        return SC_ERR_IO;
    }
    kp->pkey = pkey;
    kp->has_priv = true;

    *kp_out = kp;
    return SC_OK;
}

sc_err_t crypto_pubkey_from_raw(sc_keypair_t **kp_out,
                                const uint8_t pubkey[SC_ED25519_PUBKEY_LEN])
{
    EVP_PKEY *pkey;
    sc_keypair_t *kp;

    if (!kp_out || !pubkey)
        return SC_ERR_INVALID;

    /* EVP_PKEY_new_raw_public_key creates an EVP_PKEY from raw key bytes.
     * For Ed25519, the raw public key is exactly 32 bytes — the compressed
     * point on Curve25519. No DER/PEM envelope needed.
     * This handle can only VERIFY, not sign (no private material). */
    pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL,
                                       pubkey, SC_ED25519_PUBKEY_LEN);
    if (!pkey)
        return SC_ERR_IO;

    kp = calloc(1, sizeof(*kp));
    if (!kp) {
        EVP_PKEY_free(pkey);
        return SC_ERR_IO;
    }
    kp->pkey = pkey;
    kp->has_priv = false;

    *kp_out = kp;
    return SC_OK;
}

/* ------------------------------------------------------------------ */
/* Key Introspection                                                   */
/* ------------------------------------------------------------------ */

sc_err_t crypto_get_pubkey(const sc_keypair_t *kp,
                           uint8_t out[SC_ED25519_PUBKEY_LEN])
{
    size_t len = SC_ED25519_PUBKEY_LEN;

    if (!kp || !kp->pkey || !out)
        return SC_ERR_INVALID;

    /* EVP_PKEY_get_raw_public_key extracts the raw 32-byte public key.
     * This works on both full keypairs and public-only handles — both
     * contain the public key material. */
    if (EVP_PKEY_get_raw_public_key(kp->pkey, out, &len) <= 0 ||
        len != SC_ED25519_PUBKEY_LEN)
        return SC_ERR_IO;

    return SC_OK;
}

bool crypto_has_private(const sc_keypair_t *kp)
{
    return kp != NULL && kp->has_priv;
}

/* ------------------------------------------------------------------ */
/* Signing and Verification                                            */
/* ------------------------------------------------------------------ */

sc_err_t crypto_sign(const sc_keypair_t *kp,
                     const void *msg, size_t msg_len,
                     uint8_t sig[SC_ED25519_SIG_LEN])
{
    EVP_MD_CTX *mdctx;
    size_t siglen = SC_ED25519_SIG_LEN;
    int rc;

    if (!kp || !kp->pkey || !kp->has_priv || !sig)
        return SC_ERR_INVALID;
    if (!msg && msg_len > 0)
        return SC_ERR_INVALID;

    /* EVP_MD_CTX is a "message digest context." For most algorithms you'd
     * call DigestSignInit / DigestSignUpdate / DigestSignFinal to hash
     * incrementally. Ed25519 is different: it uses one-shot DigestSign
     * because it handles hashing internally.
     *
     * The NULL for the 'type' (3rd arg) means "use the algorithm's built-in
     * hash" — for Ed25519, that's SHA-512. You cannot choose a different hash
     * for Ed25519; it's part of the algorithm specification. */
    mdctx = EVP_MD_CTX_new();
    if (!mdctx)
        return SC_ERR_IO;

    if (EVP_DigestSignInit(mdctx, NULL, NULL, NULL, kp->pkey) <= 0) {
        EVP_MD_CTX_free(mdctx);
        return SC_ERR_IO;
    }

    /* Ensure we never pass NULL to OpenSSL for the data pointer. */
    const unsigned char *data = (msg_len > 0)
        ? (const unsigned char *)msg
        : (const unsigned char *)"";

    rc = EVP_DigestSign(mdctx, sig, &siglen, data, msg_len);
    EVP_MD_CTX_free(mdctx);

    if (rc <= 0 || siglen != SC_ED25519_SIG_LEN)
        return SC_ERR_IO;
    return SC_OK;
}

sc_err_t crypto_verify(const sc_keypair_t *kp,
                       const void *msg, size_t msg_len,
                       const uint8_t sig[SC_ED25519_SIG_LEN])
{
    EVP_MD_CTX *mdctx;
    int rc;

    if (!kp || !kp->pkey || !sig)
        return SC_ERR_INVALID;
    if (!msg && msg_len > 0)
        return SC_ERR_INVALID;

    mdctx = EVP_MD_CTX_new();
    if (!mdctx)
        return SC_ERR_IO;

    if (EVP_DigestVerifyInit(mdctx, NULL, NULL, NULL, kp->pkey) <= 0) {
        EVP_MD_CTX_free(mdctx);
        return SC_ERR_IO;
    }

    const unsigned char *data = (msg_len > 0)
        ? (const unsigned char *)msg
        : (const unsigned char *)"";

    /* EVP_DigestVerify return values:
     *   1  = signature is VALID
     *   0  = signature is INVALID (not an error — just a bad sig)
     *  <0  = an actual internal error occurred */
    rc = EVP_DigestVerify(mdctx, sig, SC_ED25519_SIG_LEN, data, msg_len);
    EVP_MD_CTX_free(mdctx);

    if (rc == 1)  return SC_OK;          /* valid signature   */
    if (rc == 0)  return SC_ERR_INVALID; /* forged/wrong sig  */
    return SC_ERR_IO;                    /* OpenSSL error     */
}

/* ------------------------------------------------------------------ */
/* SHA-256                                                             */
/* ------------------------------------------------------------------ */

sc_err_t crypto_sha256(const void *data, size_t len,
                       uint8_t hash[SC_SHA256_LEN])
{
    EVP_MD_CTX *ctx;
    unsigned int hash_len = SC_SHA256_LEN;

    if (!hash)
        return SC_ERR_INVALID;
    if (!data && len > 0)
        return SC_ERR_INVALID;

    ctx = EVP_MD_CTX_new();
    if (!ctx)
        return SC_ERR_IO;

    const unsigned char *src = (len > 0)
        ? (const unsigned char *)data
        : (const unsigned char *)"";

    /* Three-step hashing with EVP:
     *   1. DigestInit_ex: choose the hash algorithm (SHA-256)
     *   2. DigestUpdate:  feed data (can be called multiple times)
     *   3. DigestFinal_ex: produce the hash
     * Here we do it in one shot since we have all the data. */
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) <= 0 ||
        EVP_DigestUpdate(ctx, src, len) <= 0 ||
        EVP_DigestFinal_ex(ctx, hash, &hash_len) <= 0) {
        EVP_MD_CTX_free(ctx);
        return SC_ERR_IO;
    }
    EVP_MD_CTX_free(ctx);
    return SC_OK;
}

/* ------------------------------------------------------------------ */
/* Hex Encoding / Decoding                                             */
/* ------------------------------------------------------------------ */

void crypto_hex_encode(const uint8_t *in, size_t in_len, char *out)
{
    /* This table-lookup approach avoids branches and is easy to read.
     * Each byte produces exactly two hex characters. */
    static const char hx[] = "0123456789abcdef";

    for (size_t i = 0; i < in_len; i++) {
        out[i * 2]     = hx[in[i] >> 4];     /* high nibble */
        out[i * 2 + 1] = hx[in[i] & 0x0f];   /* low nibble  */
    }
    out[in_len * 2] = '\0';
}

bool crypto_hex_decode(const char *hex, uint8_t *out, size_t out_len)
{
    if (!hex || !out)
        return false;
    if (strlen(hex) != out_len * 2)
        return false;

    for (size_t i = 0; i < out_len; i++) {
        unsigned int hi, lo;
        char ch = hex[i * 2], cl = hex[i * 2 + 1];

        if      (ch >= '0' && ch <= '9') hi = (unsigned)(ch - '0');
        else if (ch >= 'a' && ch <= 'f') hi = (unsigned)(ch - 'a' + 10);
        else if (ch >= 'A' && ch <= 'F') hi = (unsigned)(ch - 'A' + 10);
        else return false;

        if      (cl >= '0' && cl <= '9') lo = (unsigned)(cl - '0');
        else if (cl >= 'a' && cl <= 'f') lo = (unsigned)(cl - 'a' + 10);
        else if (cl >= 'A' && cl <= 'F') lo = (unsigned)(cl - 'A' + 10);
        else return false;

        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

/* ------------------------------------------------------------------ */
/* Random Bytes                                                        */
/* ------------------------------------------------------------------ */

sc_err_t crypto_rand_bytes(void *buf, size_t len)
{
    if (!buf && len > 0)
        return SC_ERR_INVALID;
    if (len == 0)
        return SC_OK;
    if (len > (size_t)INT_MAX)
        return SC_ERR_INVALID;

    /* RAND_bytes uses OpenSSL's CSPRNG (cryptographically secure PRNG).
     * On Linux this is seeded from /dev/urandom or getrandom(2).
     *
     * Never use rand(), random(), or srand() for cryptographic purposes.
     * Those are LCG/Mersenne-Twister PRNGs — fast for simulations but
     * trivially predictable by an attacker who sees a few outputs. */
    if (RAND_bytes((unsigned char *)buf, (int)len) != 1)
        return SC_ERR_IO;
    return SC_OK;
}

/* ------------------------------------------------------------------ */
/* Cleanup                                                             */
/* ------------------------------------------------------------------ */

void crypto_keypair_free(sc_keypair_t *kp)
{
    if (!kp)
        return;
    if (kp->pkey)
        EVP_PKEY_free(kp->pkey);
    /* calloc'd in keygen/load/pubkey_from_raw */
    free(kp);
}
