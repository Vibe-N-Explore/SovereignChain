/* dag.c - Directed Acyclic Graph (DAG) implementation. */
#define _POSIX_C_SOURCE 200809L

#include "dag.h"

#include <stdlib.h>
#include <string.h>

#include "crypto.h"
#include "log.h"

struct sc_dag {
    sc_vertex_t vertices[SC_DAG_MAX_VERTICES];
    bool        occupied[SC_DAG_MAX_VERTICES];
    size_t      count;
};

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

static void pack_u32_be(uint8_t *dest, uint32_t val)
{
    dest[0] = (uint8_t)(val >> 24);
    dest[1] = (uint8_t)(val >> 16);
    dest[2] = (uint8_t)(val >> 8);
    dest[3] = (uint8_t)(val);
}

static uint32_t unpack_u32_be(const uint8_t *src)
{
    return ((uint32_t)src[0] << 24) |
           ((uint32_t)src[1] << 16) |
           ((uint32_t)src[2] << 8)  |
           ((uint32_t)src[3]);
}

sc_err_t dag_create(sc_dag_t **dag_out)
{
    if (!dag_out)
        return SC_ERR_INVALID;

    sc_dag_t *d = calloc(1, sizeof(*d));
    if (!d)
        return SC_ERR_IO;

    *dag_out = d;
    return SC_OK;
}

void dag_free(sc_dag_t *dag)
{
    free(dag);
}

sc_err_t vertex_compute_batch_hash(const sc_tx_t *txs, size_t count,
                                   uint8_t hash_out[SC_SHA256_LEN])
{
    if (!hash_out)
        return SC_ERR_INVALID;

    if (count == 0 || !txs) {
        /* Empty batch has deterministic SHA-256 of empty string */
        return crypto_sha256("", 0, hash_out);
    }

    /* Concatenate all tx hashes and hash */
    uint8_t buf[SC_MAX_BATCH_TXS * SC_SHA256_LEN];
    for (size_t i = 0; i < count; i++) {
        memcpy(buf + i * SC_SHA256_LEN, txs[i].hash, SC_SHA256_LEN);
    }

    return crypto_sha256(buf, count * SC_SHA256_LEN, hash_out);
}

sc_err_t vertex_compute_hash(const sc_vertex_t *v, uint8_t hash_out[SC_SHA256_LEN])
{
    if (!v || !hash_out)
        return SC_ERR_INVALID;

    /* Domain: "VERTEX/v1" (9 bytes) */
    static const uint8_t domain[9] = {'V','E','R','T','E','X','/','v','1'};

    /* Buffer: domain(9) + round(8) + author_pub(32) + tx_batch_hash(32) + parent_count(4) + parents(parent_count*32) */
    size_t payload_len = 9 + 8 + 32 + 32 + 4 + (v->parent_count * SC_SHA256_LEN);
    uint8_t buf[9 + 8 + 32 + 32 + 4 + (SC_MAX_PARENTS * SC_SHA256_LEN)];

    memcpy(buf, domain, 9);
    pack_u64_be(buf + 9, v->round);
    memcpy(buf + 17, v->author_pub, SC_ED25519_PUBKEY_LEN);
    memcpy(buf + 49, v->tx_batch_hash, SC_SHA256_LEN);
    pack_u32_be(buf + 81, (uint32_t)v->parent_count);

    for (size_t i = 0; i < v->parent_count; i++) {
        memcpy(buf + 85 + (i * SC_SHA256_LEN), v->parent_hashes[i], SC_SHA256_LEN);
    }

    return crypto_sha256(buf, payload_len, hash_out);
}

sc_err_t vertex_create(sc_vertex_t *v, uint64_t round, int author_id,
                       const sc_keypair_t *author_kp,
                       const uint8_t parent_hashes[][SC_SHA256_LEN], size_t parent_count,
                       const sc_tx_t *txs, size_t tx_count)
{
    if (!v || !author_kp || parent_count > SC_MAX_PARENTS || tx_count > SC_MAX_BATCH_TXS)
        return SC_ERR_INVALID;

    memset(v, 0, sizeof(*v));
    v->round = round;
    v->author = author_id;
    if (crypto_get_pubkey(author_kp, v->author_pub) != SC_OK)
        return SC_ERR_IO;

    v->parent_count = parent_count;
    for (size_t i = 0; i < parent_count; i++) {
        memcpy(v->parent_hashes[i], parent_hashes[i], SC_SHA256_LEN);
    }

    v->tx_count = tx_count;
    if (tx_count > 0 && txs) {
        memcpy(v->txs, txs, tx_count * sizeof(sc_tx_t));
    }

    if (vertex_compute_batch_hash(txs, tx_count, v->tx_batch_hash) != SC_OK)
        return SC_ERR_IO;

    if (vertex_compute_hash(v, v->vertex_hash) != SC_OK)
        return SC_ERR_IO;

    /* Sign canonical vertex_hash */
    if (crypto_sign(author_kp, v->vertex_hash, SC_SHA256_LEN, v->signature) != SC_OK)
        return SC_ERR_IO;

    return SC_OK;
}

sc_err_t vertex_verify_sig(const sc_vertex_t *v)
{
    if (!v)
        return SC_ERR_INVALID;

    /* Recompute expected vertex hash */
    uint8_t expected_hash[SC_SHA256_LEN];
    if (vertex_compute_hash(v, expected_hash) != SC_OK)
        return SC_ERR_IO;

    if (memcmp(expected_hash, v->vertex_hash, SC_SHA256_LEN) != 0)
        return SC_ERR_INVALID;

    /* Verify signature under author_pub */
    sc_keypair_t *pub_handle = NULL;
    sc_err_t rc = crypto_pubkey_from_raw(&pub_handle, v->author_pub);
    if (rc != SC_OK)
        return rc;

    rc = crypto_verify(pub_handle, v->vertex_hash, SC_SHA256_LEN, v->signature);
    crypto_keypair_free(pub_handle);
    return rc;
}

sc_err_t vertex_serialize(const sc_vertex_t *v, uint8_t *buf, size_t buflen, size_t *written_out)
{
    if (!v || !buf)
        return SC_ERR_INVALID;

    /* Required size: 8 (round) + 4 (author) + 32 (pub) + 32 (batch) + 32 (vhash) + 64 (sig) +
     * 4 (pcount) + pcount*32 + 4 (txcount) + txcount*152 */
    size_t req = 8 + 4 + 32 + 32 + 32 + 64 + 4 + (v->parent_count * 32) + 4 + (v->tx_count * SC_TX_WIRE_LEN);
    if (buflen < req)
        return SC_ERR_INVALID;

    uint8_t *p = buf;
    pack_u64_be(p, v->round);            p += 8;
    pack_u32_be(p, (uint32_t)v->author); p += 4;
    memcpy(p, v->author_pub, 32);        p += 32;
    memcpy(p, v->tx_batch_hash, 32);     p += 32;
    memcpy(p, v->vertex_hash, 32);       p += 32;
    memcpy(p, v->signature, 64);         p += 64;

    pack_u32_be(p, (uint32_t)v->parent_count); p += 4;
    for (size_t i = 0; i < v->parent_count; i++) {
        memcpy(p, v->parent_hashes[i], 32);
        p += 32;
    }

    pack_u32_be(p, (uint32_t)v->tx_count); p += 4;
    for (size_t i = 0; i < v->tx_count; i++) {
        size_t tx_written = 0;
        if (tx_serialize(&v->txs[i], p, SC_TX_WIRE_LEN, &tx_written) != SC_OK)
            return SC_ERR_IO;
        p += SC_TX_WIRE_LEN;
    }

    if (written_out)
        *written_out = (size_t)(p - buf);
    return SC_OK;
}

sc_err_t vertex_deserialize(sc_vertex_t *v, const uint8_t *buf, size_t buflen)
{
    if (!v || !buf || buflen < (8 + 4 + 32 + 32 + 32 + 64 + 4 + 4))
        return SC_ERR_INVALID;

    memset(v, 0, sizeof(*v));
    const uint8_t *p = buf;

    v->round  = unpack_u64_be(p); p += 8;
    v->author = (int)unpack_u32_be(p); p += 4;
    memcpy(v->author_pub, p, 32); p += 32;
    memcpy(v->tx_batch_hash, p, 32); p += 32;
    memcpy(v->vertex_hash, p, 32); p += 32;
    memcpy(v->signature, p, 64); p += 64;

    v->parent_count = unpack_u32_be(p); p += 4;
    if (v->parent_count > SC_MAX_PARENTS || (size_t)(buf + buflen - p) < (v->parent_count * 32 + 4))
        return SC_ERR_INVALID;

    for (size_t i = 0; i < v->parent_count; i++) {
        memcpy(v->parent_hashes[i], p, 32);
        p += 32;
    }

    v->tx_count = unpack_u32_be(p); p += 4;
    if (v->tx_count > SC_MAX_BATCH_TXS || (size_t)(buf + buflen - p) < (v->tx_count * SC_TX_WIRE_LEN))
        return SC_ERR_INVALID;

    for (size_t i = 0; i < v->tx_count; i++) {
        if (tx_deserialize(&v->txs[i], p, SC_TX_WIRE_LEN) != SC_OK)
            return SC_ERR_INVALID;
        p += SC_TX_WIRE_LEN;
    }

    return SC_OK;
}

sc_err_t dag_add_vertex(sc_dag_t *dag, const sc_vertex_t *v)
{
    if (!dag || !v)
        return SC_ERR_INVALID;

    /* Check if already present */
    if (dag_has_vertex(dag, v->vertex_hash))
        return SC_OK;

    if (dag->count >= SC_DAG_MAX_VERTICES)
        return SC_ERR_IO;

    for (size_t i = 0; i < SC_DAG_MAX_VERTICES; i++) {
        if (!dag->occupied[i]) {
            dag->vertices[i] = *v;
            dag->occupied[i] = true;
            dag->count++;
            return SC_OK;
        }
    }

    return SC_ERR_IO;
}

bool dag_has_vertex(const sc_dag_t *dag, const uint8_t hash[SC_SHA256_LEN])
{
    return (dag_get_vertex(dag, hash) != NULL);
}

const sc_vertex_t *dag_get_vertex(const sc_dag_t *dag, const uint8_t hash[SC_SHA256_LEN])
{
    if (!dag || !hash)
        return NULL;

    for (size_t i = 0; i < SC_DAG_MAX_VERTICES; i++) {
        if (dag->occupied[i] && memcmp(dag->vertices[i].vertex_hash, hash, SC_SHA256_LEN) == 0) {
            return &dag->vertices[i];
        }
    }
    return NULL;
}

const sc_vertex_t *dag_get_by_round_author(const sc_dag_t *dag, uint64_t round, int author)
{
    if (!dag)
        return NULL;

    for (size_t i = 0; i < SC_DAG_MAX_VERTICES; i++) {
        if (dag->occupied[i] && dag->vertices[i].round == round && dag->vertices[i].author == author) {
            return &dag->vertices[i];
        }
    }
    return NULL;
}

static void collect_causal_rec(const sc_dag_t *dag, const uint8_t hash[SC_SHA256_LEN],
                               const sc_vertex_t **out, size_t max_out, size_t *count)
{
    const sc_vertex_t *v = dag_get_vertex(dag, hash);
    if (!v || *count >= max_out)
        return;

    /* Check if already collected in out array */
    for (size_t i = 0; i < *count; i++) {
        if (memcmp(out[i]->vertex_hash, hash, SC_SHA256_LEN) == 0) {
            return;
        }
    }

    /* Recurse on parents first (depth-first traversal) */
    for (size_t p = 0; p < v->parent_count; p++) {
        collect_causal_rec(dag, v->parent_hashes[p], out, max_out, count);
    }

    /* Add this vertex */
    if (*count < max_out) {
        out[*count] = v;
        (*count)++;
    }
}

sc_err_t dag_get_causal_history(const sc_dag_t *dag, const uint8_t root_hash[SC_SHA256_LEN],
                                const sc_vertex_t **out_vertices, size_t max_out,
                                size_t *count_out)
{
    if (!dag || !root_hash || !out_vertices || !count_out)
        return SC_ERR_INVALID;

    *count_out = 0;
    collect_causal_rec(dag, root_hash, out_vertices, max_out, count_out);
    return SC_OK;
}

size_t dag_vertex_count(const sc_dag_t *dag)
{
    return dag ? dag->count : 0;
}
