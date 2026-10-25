/* consensus.c - SovereignChain Prototype DAG (SPD) consensus engine implementation. */
#define _POSIX_C_SOURCE 200809L

#include "consensus.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto.h"
#include "log.h"
#include "storage.h"

struct sc_consensus {
    network_config_t    net_cfg;
    int                 my_node_id;
    const sc_keypair_t *my_kp;
    sc_dag_t           *dag;
    sc_ledger_t        *ledger;
    sc_mempool_t       *mempool;
    char                data_dir[SC_MAX_PATH];

    sc_certificate_t    certs[SC_MAX_CERTIFICATES];
    bool                cert_occupied[SC_MAX_CERTIFICATES];
    size_t              cert_count;

    /* Committed vertices tracking */
    uint8_t             committed_hashes[SC_DAG_MAX_VERTICES][SC_SHA256_LEN];
    size_t              committed_count;
    uint64_t            last_committed_round;

    /* Equivocation tracking */
    sc_equivocation_t   equivocations[SC_MAX_EQUIVOCATIONS];
    size_t              equivocation_count;
};

static void compute_vote_hash(const uint8_t vertex_hash[SC_SHA256_LEN],
                              uint8_t vote_hash_out[SC_SHA256_LEN])
{
    /* Domain: "VOTE/v1" (7 bytes) */
    static const uint8_t domain[7] = {'V','O','T','E','/','v','1'};
    uint8_t buf[7 + SC_SHA256_LEN];
    memcpy(buf, domain, 7);
    memcpy(buf + 7, vertex_hash, SC_SHA256_LEN);
    crypto_sha256(buf, sizeof(buf), vote_hash_out);
}

sc_err_t consensus_create(sc_consensus_t **cons_out,
                          const network_config_t *net_cfg,
                          int my_node_id,
                          const sc_keypair_t *my_kp,
                          sc_dag_t *dag,
                          sc_ledger_t *ledger,
                          sc_mempool_t *mempool,
                          const char *data_dir)
{
    if (!cons_out || !net_cfg || !dag)
        return SC_ERR_INVALID;

    sc_consensus_t *c = calloc(1, sizeof(*c));
    if (!c)
        return SC_ERR_IO;

    c->net_cfg = *net_cfg;
    c->my_node_id = my_node_id;
    c->my_kp = my_kp;
    c->dag = dag;
    c->ledger = ledger;
    c->mempool = mempool;
    if (data_dir) {
        snprintf(c->data_dir, sizeof(c->data_dir), "%s", data_dir);
    }

    *cons_out = c;
    return SC_OK;
}

void consensus_free(sc_consensus_t *cons)
{
    free(cons);
}

sc_err_t consensus_vote_vertex(sc_consensus_t *cons, const sc_vertex_t *v,
                               uint8_t vote_sig_out[SC_ED25519_SIG_LEN])
{
    if (!cons || !v || !vote_sig_out)
        return SC_ERR_INVALID;

    /* 1. Only validators can author vertices */
    if (!config_node_is_validator(&cons->net_cfg, v->author)) {
        log_eventf(LOG_WARN, "consensus", "reject_vertex_author_not_validator",
                   "author=%d", v->author);
        return SC_ERR_INVALID;
    }

    /* 2. Check author signature */
    if (vertex_verify_sig(v) != SC_OK) {
        log_eventf(LOG_WARN, "consensus", "reject_vertex_invalid_signature",
                   "author=%d round=%llu", v->author, (unsigned long long)v->round);
        return SC_ERR_INVALID;
    }

    /* 3. Equivocation check: Has this author already produced a different vertex for this round? */
    const sc_vertex_t *existing = dag_get_by_round_author(cons->dag, v->round, v->author);
    if (existing && memcmp(existing->vertex_hash, v->vertex_hash, SC_SHA256_LEN) != 0) {
        /* Equivocation detected! */
        log_eventf(LOG_ERROR, "consensus", "equivocation_detected",
                   "author=%d round=%llu", v->author, (unsigned long long)v->round);

        if (cons->equivocation_count < SC_MAX_EQUIVOCATIONS) {
            sc_equivocation_t *eq = &cons->equivocations[cons->equivocation_count++];
            eq->round = v->round;
            eq->author = v->author;
            memcpy(eq->hash_a, existing->vertex_hash, SC_SHA256_LEN);
            memcpy(eq->hash_b, v->vertex_hash, SC_SHA256_LEN);
            memcpy(eq->sig_a, existing->signature, SC_ED25519_SIG_LEN);
            memcpy(eq->sig_b, v->signature, SC_ED25519_SIG_LEN);
        }
        return SC_ERR_INVALID;
    }

    /* 4. Only validators vote */
    if (!cons->my_kp || !config_node_is_validator(&cons->net_cfg, cons->my_node_id)) {
        return SC_ERR_INVALID;
    }

    /* 5. Compute vote hash and sign */
    uint8_t vote_hash[SC_SHA256_LEN];
    compute_vote_hash(v->vertex_hash, vote_hash);

    if (crypto_sign(cons->my_kp, vote_hash, SC_SHA256_LEN, vote_sig_out) != SC_OK) {
        return SC_ERR_IO;
    }

    return SC_OK;
}

sc_err_t consensus_add_vote(sc_consensus_t *cons, const uint8_t vertex_hash[SC_SHA256_LEN],
                            int voter_id, const uint8_t sig[SC_ED25519_SIG_LEN],
                            bool *is_certified_out)
{
    if (is_certified_out)
        *is_certified_out = false;

    if (!cons || !vertex_hash || !sig)
        return SC_ERR_INVALID;

    if (voter_id < 0 || voter_id > 1)
        return SC_ERR_INVALID; /* Only validators 0 and 1 */

    /* Verify signature against pinned validator key */
    const node_info_t *voter = config_find_node(&cons->net_cfg, voter_id);
    if (!voter || !voter->has_pubkey || voter->role != ROLE_VALIDATOR)
        return SC_ERR_INVALID;

    uint8_t vote_hash[SC_SHA256_LEN];
    compute_vote_hash(vertex_hash, vote_hash);

    sc_keypair_t *pub_handle = NULL;
    if (crypto_pubkey_from_raw(&pub_handle, voter->pubkey) != SC_OK)
        return SC_ERR_IO;

    sc_err_t rc = crypto_verify(pub_handle, vote_hash, SC_SHA256_LEN, sig);
    crypto_keypair_free(pub_handle);
    if (rc != SC_OK)
        return SC_ERR_INVALID;

    /* Find or create certificate entry */
    sc_certificate_t *cert = NULL;
    for (size_t i = 0; i < SC_MAX_CERTIFICATES; i++) {
        if (cons->cert_occupied[i] && memcmp(cons->certs[i].vertex_hash, vertex_hash, SC_SHA256_LEN) == 0) {
            cert = &cons->certs[i];
            break;
        }
    }

    if (!cert) {
        for (size_t i = 0; i < SC_MAX_CERTIFICATES; i++) {
            if (!cons->cert_occupied[i]) {
                cons->cert_occupied[i] = true;
                cons->cert_count++;
                cert = &cons->certs[i];
                memset(cert, 0, sizeof(*cert));
                memcpy(cert->vertex_hash, vertex_hash, SC_SHA256_LEN);

                const sc_vertex_t *v = dag_get_vertex(cons->dag, vertex_hash);
                if (v) {
                    cert->round = v->round;
                    cert->author = v->author;
                }
                break;
            }
        }
    }

    if (!cert)
        return SC_ERR_IO;

    memcpy(cert->sigs[voter_id], sig, SC_ED25519_SIG_LEN);
    cert->has_sig[voter_id] = true;

    /* Check 2-of-2 quorum */
    if (cert->has_sig[0] && cert->has_sig[1]) {
        if (is_certified_out)
            *is_certified_out = true;
    }

    return SC_OK;
}

sc_err_t consensus_verify_certificate(const sc_consensus_t *cons, const sc_certificate_t *cert)
{
    if (!cons || !cert)
        return SC_ERR_INVALID;

    if (!cert->has_sig[0] || !cert->has_sig[1])
        return SC_ERR_INVALID; /* Quorum requires 2 of 2 */

    uint8_t vote_hash[SC_SHA256_LEN];
    compute_vote_hash(cert->vertex_hash, vote_hash);

    for (int vid = 0; vid < 2; vid++) {
        const node_info_t *voter = config_find_node(&cons->net_cfg, vid);
        if (!voter || !voter->has_pubkey || voter->role != ROLE_VALIDATOR)
            return SC_ERR_INVALID;

        sc_keypair_t *pub_handle = NULL;
        if (crypto_pubkey_from_raw(&pub_handle, voter->pubkey) != SC_OK)
            return SC_ERR_IO;

        sc_err_t rc = crypto_verify(pub_handle, vote_hash, SC_SHA256_LEN, cert->sigs[vid]);
        crypto_keypair_free(pub_handle);
        if (rc != SC_OK)
            return SC_ERR_INVALID;
    }

    return SC_OK;
}

sc_err_t consensus_add_certificate(sc_consensus_t *cons, const sc_certificate_t *cert)
{
    if (!cons || !cert)
        return SC_ERR_INVALID;

    sc_err_t rc = consensus_verify_certificate(cons, cert);
    if (rc != SC_OK)
        return rc;

    for (size_t i = 0; i < SC_MAX_CERTIFICATES; i++) {
        if (cons->cert_occupied[i] && memcmp(cons->certs[i].vertex_hash, cert->vertex_hash, SC_SHA256_LEN) == 0) {
            cons->certs[i] = *cert;
            return SC_OK;
        }
    }

    for (size_t i = 0; i < SC_MAX_CERTIFICATES; i++) {
        if (!cons->cert_occupied[i]) {
            cons->cert_occupied[i] = true;
            cons->certs[i] = *cert;
            cons->cert_count++;
            return SC_OK;
        }
    }

    return SC_ERR_IO;
}

bool consensus_is_certified(const sc_consensus_t *cons, const uint8_t vertex_hash[SC_SHA256_LEN])
{
    const sc_certificate_t *cert = consensus_get_certificate(cons, vertex_hash);
    return (cert != NULL && cert->has_sig[0] && cert->has_sig[1]);
}

const sc_certificate_t *consensus_get_certificate(const sc_consensus_t *cons,
                                                  const uint8_t vertex_hash[SC_SHA256_LEN])
{
    if (!cons || !vertex_hash)
        return NULL;

    for (size_t i = 0; i < SC_MAX_CERTIFICATES; i++) {
        if (cons->cert_occupied[i] && memcmp(cons->certs[i].vertex_hash, vertex_hash, SC_SHA256_LEN) == 0) {
            return &cons->certs[i];
        }
    }
    return NULL;
}

static bool is_already_committed(const sc_consensus_t *cons, const uint8_t hash[SC_SHA256_LEN])
{
    for (size_t i = 0; i < cons->committed_count; i++) {
        if (memcmp(cons->committed_hashes[i], hash, SC_SHA256_LEN) == 0)
            return true;
    }
    return false;
}

static int compare_vertices_deterministic(const void *a, const void *b)
{
    const sc_vertex_t *v1 = *(const sc_vertex_t **)a;
    const sc_vertex_t *v2 = *(const sc_vertex_t **)b;

    /* 1. Sort by round ASC */
    if (v1->round != v2->round)
        return (v1->round < v2->round) ? -1 : 1;

    /* 2. Sort by author ASC */
    if (v1->author != v2->author)
        return (v1->author < v2->author) ? -1 : 1;

    /* 3. Lexicographical comparison of vertex hash */
    return memcmp(v1->vertex_hash, v2->vertex_hash, SC_SHA256_LEN);
}

sc_err_t consensus_evaluate_commits(sc_consensus_t *cons, size_t *committed_count_out)
{
    if (committed_count_out)
        *committed_count_out = 0;

    if (!cons)
        return SC_ERR_INVALID;

    size_t newly_committed = 0;

    /* Check anchors sequentially from last_committed_round + 1 */
    uint64_t candidate_round = cons->last_committed_round + 1;
    if (candidate_round == 0)
        candidate_round = 1;

    while (true) {
        int anchor_author = consensus_anchor_leader(candidate_round);
        const sc_vertex_t *anchor = dag_get_by_round_author(cons->dag, candidate_round, anchor_author);
        if (!anchor)
            break;

        /* Anchor must be certified */
        if (!consensus_is_certified(cons, anchor->vertex_hash))
            break;

        /* Check if a certified vertex in round candidate_round + 1 by the OTHER validator references this anchor */
        int other_validator = (anchor_author == 0) ? 1 : 0;
        const sc_vertex_t *next_vertex = dag_get_by_round_author(cons->dag, candidate_round + 1, other_validator);
        if (!next_vertex)
            break;

        if (!consensus_is_certified(cons, next_vertex->vertex_hash))
            break;

        bool references_anchor = false;
        for (size_t p = 0; p < next_vertex->parent_count; p++) {
            if (memcmp(next_vertex->parent_hashes[p], anchor->vertex_hash, SC_SHA256_LEN) == 0) {
                references_anchor = true;
                break;
            }
        }

        if (!references_anchor)
            break;

        /* COMMIT RULE MET FOR candidate_round ANCHOR! */
        /* Gather causal history */
        const sc_vertex_t *history[SC_DAG_MAX_VERTICES];
        size_t hist_count = 0;
        dag_get_causal_history(cons->dag, anchor->vertex_hash, history, SC_DAG_MAX_VERTICES, &hist_count);

        /* Filter to uncommitted vertices */
        const sc_vertex_t *to_order[SC_DAG_MAX_VERTICES];
        size_t order_count = 0;
        for (size_t i = 0; i < hist_count; i++) {
            if (!is_already_committed(cons, history[i]->vertex_hash)) {
                to_order[order_count++] = history[i];
            }
        }

        /* Deterministic topological sort */
        qsort(to_order, order_count, sizeof(const sc_vertex_t *), compare_vertices_deterministic);

        /* Execute transactions against Phase 7 Ledger */
        for (size_t i = 0; i < order_count; i++) {
            const sc_vertex_t *v = to_order[i];

            if (cons->ledger && v->tx_count > 0) {
                size_t applied = 0;
                ledger_apply_block(cons->ledger, v->txs, v->tx_count, false, &applied);

                /* Remove executed transactions from mempool */
                if (cons->mempool) {
                    for (size_t t = 0; t < v->tx_count; t++) {
                        mempool_remove(cons->mempool, v->txs[t].hash);
                    }
                }
            }

            /* Record as committed */
            if (cons->committed_count < SC_DAG_MAX_VERTICES) {
                memcpy(cons->committed_hashes[cons->committed_count++], v->vertex_hash, SC_SHA256_LEN);
            }
            newly_committed++;
        }

        /* Update persisted state if storage directory is configured */
        if (cons->ledger && cons->data_dir[0] != '\0') {
            char err[128];
            storage_save_state(cons->ledger, cons->data_dir, err, sizeof(err));
        }

        log_eventf(LOG_INFO, "consensus", "anchor_committed",
                   "round=%llu leader=%d ordered=%zu",
                   (unsigned long long)candidate_round, anchor_author, order_count);

        cons->last_committed_round = candidate_round;
        candidate_round++;
    }

    if (committed_count_out)
        *committed_count_out = newly_committed;

    return SC_OK;
}

bool consensus_has_equivocation(const sc_consensus_t *cons)
{
    return cons ? (cons->equivocation_count > 0) : false;
}

size_t consensus_equivocation_count(const sc_consensus_t *cons)
{
    return cons ? cons->equivocation_count : 0;
}

uint64_t consensus_latest_committed_round(const sc_consensus_t *cons)
{
    return cons ? cons->last_committed_round : 0;
}
