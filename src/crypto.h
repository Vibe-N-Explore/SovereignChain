/* crypto.h - Ed25519 signatures, SHA-256 hashing, and related utilities.
 *
 * All cryptographic operations use OpenSSL's EVP (Envelope) interface —
 * the modern, algorithm-agnostic API. Instead of calling algorithm-specific
 * functions (e.g., RSA_sign()), you call EVP_DigestSign() and pass in the
 * appropriate key type. This means switching algorithms later would only
 * require changing key setup, not every call site.
 *
 * Ed25519 key facts:
 *   - 32-byte public key, 64-byte signature
 *   - Deterministic: signing the same message always produces the same sig
 *   - Fast, constant-time (side-channel resistant)
 *   - No separate hash step: EdDSA hashes internally with SHA-512
 *
 * NOTE: This module provides AUTHENTICATION (proving who sent a message)
 * but NOT CONFIDENTIALITY (encryption). Wire traffic is readable by anyone.
 * TLS is deferred to a later phase. We document this explicitly.
 */
#ifndef SC_CRYPTO_H
#define SC_CRYPTO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "err.h"

/* ---- Ed25519 constants ---- */
#define SC_ED25519_PUBKEY_LEN  32
#define SC_ED25519_SIG_LEN     64
#define SC_PUBKEY_HEX_LEN     (SC_ED25519_PUBKEY_LEN * 2)  /* 64 hex chars */

/* ---- SHA-256 constant ---- */
#define SC_SHA256_LEN          32

/* ---- Challenge nonce size for the handshake ---- */
#define SC_NONCE_LEN           32

/* Opaque keypair handle.
 *
 * "Opaque" means callers never see the struct's internals — they only
 * hold pointers and call the crypto_* functions. The struct definition
 * lives in crypto.c, so callers can't peek inside. This is a standard C
 * pattern for information hiding:
 *   - Forward-declare the struct in the header (typedef ... sc_keypair_t)
 *   - Define it in the .c file
 *   - Callers can only allocate/free via your API
 * Benefit: you can change the struct's layout without recompiling callers.
 */
typedef struct sc_keypair sc_keypair_t;

/* ---- Key Generation ---- */

/* Generate a fresh Ed25519 keypair using OpenSSL's CSPRNG.
 * Caller must eventually call crypto_keypair_free(). */
sc_err_t crypto_keygen(sc_keypair_t **kp_out);

/* ---- Key I/O ---- */

/* Save the private key to a PEM file (mode 0600 for security).
 * PEM is the standard Base64-encoded format with -----BEGIN/END----- markers. */
sc_err_t crypto_save_privkey(const sc_keypair_t *kp, const char *path);

/* Load a private key from a PEM file. The public key is derived automatically.
 * Caller must call crypto_keypair_free(). */
sc_err_t crypto_load_privkey(sc_keypair_t **kp_out, const char *path,
                             char *errbuf, size_t errlen);

/* Create a keypair handle from a raw 32-byte public key (no private key).
 * Used for VERIFICATION only — you cannot sign with this handle.
 * Caller must call crypto_keypair_free(). */
sc_err_t crypto_pubkey_from_raw(sc_keypair_t **kp_out,
                                const uint8_t pubkey[SC_ED25519_PUBKEY_LEN]);

/* ---- Key Introspection ---- */

/* Extract the raw 32-byte public key from a keypair.
 * Works for both full keypairs and public-only handles. */
sc_err_t crypto_get_pubkey(const sc_keypair_t *kp,
                           uint8_t out[SC_ED25519_PUBKEY_LEN]);

/* Returns true if the keypair has a private key (can sign). */
bool crypto_has_private(const sc_keypair_t *kp);

/* ---- Signing and Verification ---- */

/* Sign 'msg' (of 'msg_len' bytes) with the private key.
 * Ed25519 is a "one-shot" signer: it hashes internally with SHA-512.
 * Fails if the keypair is public-only. */
sc_err_t crypto_sign(const sc_keypair_t *kp,
                     const void *msg, size_t msg_len,
                     uint8_t sig[SC_ED25519_SIG_LEN]);

/* Verify that 'sig' is a valid Ed25519 signature of 'msg' under this key.
 * Returns SC_OK if valid, SC_ERR_INVALID if the signature is bad.
 * Works with both full and public-only keypairs. */
sc_err_t crypto_verify(const sc_keypair_t *kp,
                       const void *msg, size_t msg_len,
                       const uint8_t sig[SC_ED25519_SIG_LEN]);

/* ---- SHA-256 ---- */

/* Compute SHA-256 hash of 'data'. One-shot convenience function.
 * SHA-256 produces a 32-byte (256-bit) digest. We'll use it later for
 * vertex hashing, transaction IDs, and state hashing. */
sc_err_t crypto_sha256(const void *data, size_t len,
                       uint8_t hash[SC_SHA256_LEN]);

/* ---- Hex Encoding ---- */

/* Encode binary bytes to lowercase hex string (null-terminated).
 * 'out' must have room for in_len*2 + 1 bytes. */
void crypto_hex_encode(const uint8_t *in, size_t in_len, char *out);

/* Decode hex string to binary. Returns false if hex is invalid or wrong
 * length. 'hex' must have exactly out_len*2 hex characters. */
bool crypto_hex_decode(const char *hex, uint8_t *out, size_t out_len);

/* ---- Random Bytes ---- */

/* Fill 'buf' with cryptographically secure random bytes.
 * Uses OpenSSL's CSPRNG (seeded from /dev/urandom or getrandom()).
 * NEVER use rand()/random() for crypto — those are predictable. */
sc_err_t crypto_rand_bytes(void *buf, size_t len);

/* ---- Cleanup ---- */

/* Free a keypair handle. NULL-safe. */
void crypto_keypair_free(sc_keypair_t *kp);

#endif /* SC_CRYPTO_H */
