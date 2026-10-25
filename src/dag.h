/* dag.h - Directed Acyclic Graph (DAG) construction, vertex validation, and storage.
 *
 * Phase 5: DAG Construction.
 *
 * Implements the vertex graph for the SovereignChain Prototype DAG (SPD):
 *   - Vertex structure: (round, author, tx_batch, parents, signature, vertex_hash)
 *   - Canonical hashing with domain separator "VERTEX/v1"
 *   - Author signature verification against pinned validator keys
 *   - Parent validity checks (round monotonicity and quorum linking)
 *   - In-memory DAG storage, hash indexing, and causal history traversal
 */
#ifndef SC_DAG_H
#define SC_DAG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "crypto.h"
#include "err.h"
#include "tx.h"

#define SC_MAX_PARENTS    8
#define SC_MAX_BATCH_TXS 32
#define SC_DAG_MAX_VERTICES 2048

typedef struct {
    uint64_t round;
    int      author;                                 /* author validator node id (0 or 1) */
    uint8_t  author_pub[SC_ED25519_PUBKEY_LEN];
    uint8_t  tx_batch_hash[SC_SHA256_LEN];
    size_t   tx_count;
    sc_tx_t  txs[SC_MAX_BATCH_TXS];
    size_t   parent_count;
    uint8_t  parent_hashes[SC_MAX_PARENTS][SC_SHA256_LEN];
    uint8_t  signature[SC_ED25519_SIG_LEN];         /* author's signature */
    uint8_t  vertex_hash[SC_SHA256_LEN];            /* SHA-256 digest with domain separation */
} sc_vertex_t;

typedef struct sc_dag sc_dag_t;

/* Create an empty DAG */
sc_err_t dag_create(sc_dag_t **dag_out);

/* Free all memory allocated by the DAG */
void dag_free(sc_dag_t *dag);

/* Compute the canonical SHA-256 hash of a vertex under domain "VERTEX/v1" */
sc_err_t vertex_compute_hash(const sc_vertex_t *v, uint8_t hash_out[SC_SHA256_LEN]);

/* Compute the tx_batch_hash from an array of transactions */
sc_err_t vertex_compute_batch_hash(const sc_tx_t *txs, size_t count,
                                   uint8_t hash_out[SC_SHA256_LEN]);

/* Create and sign a new vertex by author_kp */
sc_err_t vertex_create(sc_vertex_t *v, uint64_t round, int author_id,
                       const sc_keypair_t *author_kp,
                       const uint8_t parent_hashes[][SC_SHA256_LEN], size_t parent_count,
                       const sc_tx_t *txs, size_t tx_count);

/* Verify the cryptographic signature on a vertex */
sc_err_t vertex_verify_sig(const sc_vertex_t *v);

/* Serialize vertex to binary format for network transmission */
sc_err_t vertex_serialize(const sc_vertex_t *v, uint8_t *buf, size_t buflen, size_t *written_out);

/* Deserialize vertex from binary format */
sc_err_t vertex_deserialize(sc_vertex_t *v, const uint8_t *buf, size_t buflen);

/* Add a validated vertex to the DAG */
sc_err_t dag_add_vertex(sc_dag_t *dag, const sc_vertex_t *v);

/* Check if vertex exists in DAG by hash */
bool dag_has_vertex(const sc_dag_t *dag, const uint8_t hash[SC_SHA256_LEN]);

/* Retrieve vertex by hash */
const sc_vertex_t *dag_get_vertex(const sc_dag_t *dag, const uint8_t hash[SC_SHA256_LEN]);

/* Retrieve vertex by round and author ID */
const sc_vertex_t *dag_get_by_round_author(const sc_dag_t *dag, uint64_t round, int author);

/* Traverse and collect all ancestor vertices in the causal history of vertex 'root_hash'.
 * Collects up to max_out vertices into out_vertices (not ordered yet). */
sc_err_t dag_get_causal_history(const sc_dag_t *dag, const uint8_t root_hash[SC_SHA256_LEN],
                                const sc_vertex_t **out_vertices, size_t max_out,
                                size_t *count_out);

/* Return total number of vertices in DAG */
size_t dag_vertex_count(const sc_dag_t *dag);

#endif /* SC_DAG_H */
