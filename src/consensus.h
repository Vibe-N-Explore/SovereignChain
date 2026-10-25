/* consensus.h - SovereignChain Prototype DAG (SPD) consensus engine.
 *
 * Phase 6: Consensus.
 *
 * Implements the 2-of-2 certified DAG consensus protocol:
 *   - Quorum requirement: 2 of 2 validator signatures for certification (f = 0)
 *   - Alternating anchors: Round 1 -> Validator 0, Round 2 -> Validator 1, ...
 *   - Commit rule: Anchor at round r commits when round r+1 vertex of opposite validator references it
 *   - Deterministic ordering of causal history: (round ASC, author ASC, vertex_hash ASC)
 *   - Equivocation detection and evidence recording
 *   - Deterministic execution callback feeding Phase 7 Ledger and Phase 8 Persistence
 */
#ifndef SC_CONSENSUS_H
#define SC_CONSENSUS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "config.h"
#include "crypto.h"
#include "dag.h"
#include "err.h"
#include "ledger.h"
#include "mempool.h"

#define SC_MAX_CERTIFICATES 2048
#define SC_MAX_EQUIVOCATIONS 64

/* Certificate of availability: 2-of-2 validator signatures */
typedef struct {
    uint8_t  vertex_hash[SC_SHA256_LEN];
    uint64_t round;
    int      author;
    uint8_t  sigs[2][SC_ED25519_SIG_LEN]; /* sigs[0] from val 0, sigs[1] from val 1 */
    bool     has_sig[2];
} sc_certificate_t;

/* Equivocation proof record */
typedef struct {
    uint64_t round;
    int      author;
    uint8_t  hash_a[SC_SHA256_LEN];
    uint8_t  hash_b[SC_SHA256_LEN];
    uint8_t  sig_a[SC_ED25519_SIG_LEN];
    uint8_t  sig_b[SC_ED25519_SIG_LEN];
} sc_equivocation_t;

typedef struct sc_consensus sc_consensus_t;

/* Create a new consensus instance */
sc_err_t consensus_create(sc_consensus_t **cons_out,
                          const network_config_t *net_cfg,
                          int my_node_id,
                          const sc_keypair_t *my_kp,
                          sc_dag_t *dag,
                          sc_ledger_t *ledger,
                          sc_mempool_t *mempool,
                          const char *data_dir);

/* Free all memory allocated by consensus */
void consensus_free(sc_consensus_t *cons);

/* Vote on a received vertex:
 *   - Validates author permission from network.conf
 *   - Checks for equivocation
 *   - If valid, produces a signature under domain "VOTE/v1" */
sc_err_t consensus_vote_vertex(sc_consensus_t *cons, const sc_vertex_t *v,
                               uint8_t vote_sig_out[SC_ED25519_SIG_LEN]);

/* Add a validator's vote to a vertex certificate.
 * Returns true if certificate reached 2-of-2 quorum */
sc_err_t consensus_add_vote(sc_consensus_t *cons, const uint8_t vertex_hash[SC_SHA256_LEN],
                            int voter_id, const uint8_t sig[SC_ED25519_SIG_LEN],
                            bool *is_certified_out);

/* Verify a certificate (checks both signatures against pinned validator keys) */
sc_err_t consensus_verify_certificate(const sc_consensus_t *cons, const sc_certificate_t *cert);

/* Record a certificate */
sc_err_t consensus_add_certificate(sc_consensus_t *cons, const sc_certificate_t *cert);

/* Check if a vertex is certified */
bool consensus_is_certified(const sc_consensus_t *cons, const uint8_t vertex_hash[SC_SHA256_LEN]);

/* Retrieve certificate by vertex hash */
const sc_certificate_t *consensus_get_certificate(const sc_consensus_t *cons,
                                                  const uint8_t vertex_hash[SC_SHA256_LEN]);

/* Predetermined anchor leader for round r:
 * Round 1: Node 0, Round 2: Node 1, Round 3: Node 0, ... */
static inline int consensus_anchor_leader(uint64_t round)
{
    return (int)((round % 2 == 1) ? 0 : 1);
}

/* Evaluate the commit rule on the DAG up to the latest certified round.
 * Returns number of newly committed vertices. */
sc_err_t consensus_evaluate_commits(sc_consensus_t *cons, size_t *committed_count_out);

/* Check if any equivocation was detected */
bool consensus_has_equivocation(const sc_consensus_t *cons);

/* Retrieve count of detected equivocations */
size_t consensus_equivocation_count(const sc_consensus_t *cons);

/* Return latest committed anchor round */
uint64_t consensus_latest_committed_round(const sc_consensus_t *cons);

#endif /* SC_CONSENSUS_H */
