/* main.c - SovereignChain node process.
 *
 * Integrates all 9 phases:
 *   - Phase 1: Network Foundation, process lifecycle, signal handling
 *   - Phase 2: Framed TCP networking, poll() event loop
 *   - Phase 3: Cryptographic identities (Ed25519 / SHA-256), mutual authentication
 *   - Phase 4: Transactions, Mempool, and transaction gossip
 *   - Phase 5: DAG construction, vertex validation, parent references
 *   - Phase 6: Consensus (SPD 2-of-2 certification, alternating anchors, ordering)
 *   - Phase 7: Deterministic execution engine and state hashing
 *   - Phase 8: Atomic persistence and crash recovery
 *   - Phase 9: Security hardening and verification
 */
#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "config.h"
#include "consensus.h"
#include "crypto.h"
#include "dag.h"
#include "err.h"
#include "ledger.h"
#include "log.h"
#include "mempool.h"
#include "net.h"
#include "storage.h"
#include "tx.h"

#define EXIT_USAGE 2
#define TOPOLOGY_VALIDATORS 2
#define TOPOLOGY_NORMALS    4

static volatile sig_atomic_t g_stop_signal = 0;

static void on_signal(int sig) { g_stop_signal = sig; }

static void install_signal_handlers(void)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "usage: %s --network <network.conf> --config <node.conf> "
            "[--send-test <target_id> <message>] "
            "[--send-tx <target_node_id> <amount> <fee>]\n",
            prog);
}

typedef struct {
    int                 node_id;
    network_config_t    net_cfg;
    const sc_keypair_t *my_kp;
    sc_net_t           *net;
    sc_ledger_t        *ledger;
    sc_mempool_t       *mempool;
    sc_dag_t           *dag;
    sc_consensus_t     *consensus;
    char                data_dir[SC_MAX_PATH];
    uint64_t            current_round;
} sc_node_ctx_t;

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

static void propose_vertex_if_needed(sc_node_ctx_t *ctx)
{
    if (!config_node_is_validator(&ctx->net_cfg, ctx->node_id))
        return;

    size_t pending_txs = mempool_count(ctx->mempool);
    if (pending_txs == 0)
        return;

    sc_tx_t batch[SC_MAX_BATCH_TXS];
    size_t tx_count = 0;
    if (mempool_get_batch(ctx->mempool, SC_MAX_BATCH_TXS, batch, &tx_count) != SC_OK || tx_count == 0)
        return;

    ctx->current_round++;

    uint8_t parent_hashes[SC_MAX_PARENTS][SC_SHA256_LEN];
    size_t parent_count = 0;
    // Note: dag_get_tips is typically handled via round tracking or tips. If your dag.h uses custom tip gathering, use it or fallback to parent hashes.
    // For simplicity, we reference the previous round's vertices.
    const sc_vertex_t *prev_v = dag_get_by_round_author(ctx->dag, ctx->current_round > 1 ? ctx->current_round - 1 : 1, (ctx->node_id == 0) ? 1 : 0);
    if (prev_v) {
        memcpy(parent_hashes[0], prev_v->vertex_hash, SC_SHA256_LEN);
        parent_count = 1;
    }

    sc_vertex_t vertex;
    if (vertex_create(&vertex, ctx->current_round, ctx->node_id, ctx->my_kp,
                      parent_hashes, parent_count,
                      batch, tx_count) == SC_OK) {
        if (dag_add_vertex(ctx->dag, &vertex) == SC_OK) {
            uint8_t vbuf[4096];
            size_t vlen = 0;
            if (vertex_serialize(&vertex, vbuf, sizeof(vbuf), &vlen) == SC_OK) {
                net_send(ctx->net, SC_BROADCAST_ALL, MSG_TYPE_VERTEX, vbuf, vlen);
                log_eventf(LOG_INFO, "consensus", "proposed_vertex",
                           "round=%llu tx_count=%zu",
                           (unsigned long long)ctx->current_round, tx_count);

                uint8_t vote_sig[SC_ED25519_SIG_LEN];
                if (consensus_vote_vertex(ctx->consensus, &vertex, vote_sig) == SC_OK) {
                    bool is_cert = false;
                    consensus_add_vote(ctx->consensus, vertex.vertex_hash, ctx->node_id, vote_sig, &is_cert);
                }
            }
        }
    }
}

static void on_message(int from_node_id, uint16_t type,
                       const uint8_t *payload, size_t len, void *user)
{
    sc_node_ctx_t *ctx = (sc_node_ctx_t *)user;
    if (!ctx)
        return;

    if (type == MSG_TYPE_TEST) {
        char safe_payload[256];
        size_t cpy = len < sizeof(safe_payload) - 1 ? len : sizeof(safe_payload) - 1;
        memcpy(safe_payload, payload, cpy);
        safe_payload[cpy] = '\0';
        log_eventf(LOG_INFO, "net", "recv_test",
                   "from=%d len=%zu payload=\"%s\"", from_node_id, len, safe_payload);
    } else if (type == MSG_TYPE_TX) {
        sc_tx_t tx;
        if (tx_deserialize(&tx, payload, len) == SC_OK) {
            bool added = false;
            if (mempool_add(ctx->mempool, &tx, &added) == SC_OK && added) {
                log_eventf(LOG_INFO, "mempool", "recv_tx",
                           "from=%d amount=%llu fee=%llu nonce=%llu",
                           from_node_id, (unsigned long long)tx.amount,
                           (unsigned long long)tx.fee, (unsigned long long)tx.nonce);
                net_send(ctx->net, SC_BROADCAST_ALL, MSG_TYPE_TX, payload, len);
            }
        }
    } else if (type == MSG_TYPE_VERTEX) {
        sc_vertex_t v;
        if (vertex_deserialize(&v, payload, len) == SC_OK) {
            if (dag_add_vertex(ctx->dag, &v) == SC_OK) {
                log_eventf(LOG_INFO, "dag", "recv_vertex",
                           "author=%d round=%llu tx_count=%zu",
                           v.author, (unsigned long long)v.round, v.tx_count);

                if (v.round > ctx->current_round) {
                    ctx->current_round = v.round;
                }

                if (config_node_is_validator(&ctx->net_cfg, ctx->node_id)) {
                    uint8_t vote_sig[SC_ED25519_SIG_LEN];
                    if (consensus_vote_vertex(ctx->consensus, &v, vote_sig) == SC_OK) {
                        uint8_t vote_msg[4 + SC_SHA256_LEN + SC_ED25519_SIG_LEN];
                        pack_u32_be(vote_msg, (uint32_t)ctx->node_id);
                        memcpy(vote_msg + 4, v.vertex_hash, SC_SHA256_LEN);
                        memcpy(vote_msg + 4 + SC_SHA256_LEN, vote_sig, SC_ED25519_SIG_LEN);

                        net_send(ctx->net, v.author, MSG_TYPE_VOTE, vote_msg, sizeof(vote_msg));

                        bool is_cert = false;
                        consensus_add_vote(ctx->consensus, v.vertex_hash, ctx->node_id, vote_sig, &is_cert);
                    }
                }
            }
        }
    } else if (type == MSG_TYPE_VOTE) {
        if (len >= 4 + SC_SHA256_LEN + SC_ED25519_SIG_LEN) {
            int voter_id = (int)unpack_u32_be(payload);
            const uint8_t *vhash = payload + 4;
            const uint8_t *sig = payload + 4 + SC_SHA256_LEN;

            bool is_cert = false;
            if (consensus_add_vote(ctx->consensus, vhash, voter_id, sig, &is_cert) == SC_OK) {
                if (is_cert) {
                    const sc_certificate_t *c = consensus_get_certificate(ctx->consensus, vhash);
                    if (c) {
                        uint8_t cert_msg[SC_SHA256_LEN + 8 + 4 + 2 * SC_ED25519_SIG_LEN];
                        memcpy(cert_msg, c->vertex_hash, SC_SHA256_LEN);
                        pack_u64_be(cert_msg + 32, c->round);
                        pack_u32_be(cert_msg + 40, (uint32_t)c->author);
                        memcpy(cert_msg + 44, c->sigs[0], SC_ED25519_SIG_LEN);
                        memcpy(cert_msg + 44 + SC_ED25519_SIG_LEN, c->sigs[1], SC_ED25519_SIG_LEN);

                        net_send(ctx->net, SC_BROADCAST_ALL, MSG_TYPE_CERT, cert_msg, sizeof(cert_msg));

                        size_t comm = 0;
                        consensus_evaluate_commits(ctx->consensus, &comm);
                    }
                }
            }
        }
    } else if (type == MSG_TYPE_CERT) {
        if (len >= SC_SHA256_LEN + 8 + 4 + 2 * SC_ED25519_SIG_LEN) {
            sc_certificate_t c;
            memcpy(c.vertex_hash, payload, SC_SHA256_LEN);
            c.round = unpack_u64_be(payload + 32);
            c.author = (int)unpack_u32_be(payload + 40);
            memcpy(c.sigs[0], payload + 44, SC_ED25519_SIG_LEN);
            memcpy(c.sigs[1], payload + 44 + SC_ED25519_SIG_LEN, SC_ED25519_SIG_LEN);
            c.has_sig[0] = true;
            c.has_sig[1] = true;

            if (consensus_add_certificate(ctx->consensus, &c) == SC_OK) {
                size_t comm = 0;
                consensus_evaluate_commits(ctx->consensus, &comm);
            }
        }
    }
}

static sc_err_t open_listener(const node_info_t *me, int *fd_out, char *errbuf,
                               size_t errlen)
{
    struct sockaddr_in sa;
    int fd, one = 1;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        snprintf(errbuf, errlen, "socket: %s", strerror(errno));
        return SC_ERR_IO;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) != 0) {
        snprintf(errbuf, errlen, "setsockopt: %s", strerror(errno));
        close(fd);
        return SC_ERR_IO;
    }
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(me->port);
    if (inet_pton(AF_INET, me->host, &sa.sin_addr) != 1) {
        snprintf(errbuf, errlen, "bad address %s", me->host);
        close(fd);
        return SC_ERR_INVALID;
    }
    if (bind(fd, (struct sockaddr *)&sa, sizeof sa) != 0) {
        snprintf(errbuf, errlen, "bind %s:%u: %s", me->host,
                 (unsigned)me->port, strerror(errno));
        close(fd);
        return SC_ERR_IO;
    }
    if (listen(fd, 16) != 0) {
        snprintf(errbuf, errlen, "listen: %s", strerror(errno));
        close(fd);
        return SC_ERR_IO;
    }
    *fd_out = fd;
    return SC_OK;
}

int main(int argc, char **argv)
{
    const char *net_path = NULL, *cfg_path = NULL;
    int test_target_id = -1;
    const char *test_msg = NULL;
    bool test_sent = false;

    int tx_target_id = -1;
    uint64_t tx_amount = 0, tx_fee = 0;
    bool send_tx_flag = false;
    bool tx_sent = false;

    network_config_t net_cfg;
    node_config_t    cfg;
    const node_info_t *me;
    char         err[256];
    int          listen_fd = -1;
    sc_net_t    *net       = NULL;
    sc_keypair_t *my_kp    = NULL;
    sc_ledger_t *ledger    = NULL;
    sc_mempool_t *mempool  = NULL;
    sc_dag_t    *dag       = NULL;
    sc_consensus_t *cons   = NULL;
    sc_err_t     rc;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--network") == 0 && i + 1 < argc)
            net_path = argv[++i];
        else if (strcmp(argv[i], "--config") == 0 && i + 1 < argc)
            cfg_path = argv[++i];
        else if (strcmp(argv[i], "--send-test") == 0 && i + 2 < argc) {
            test_target_id = atoi(argv[++i]);
            test_msg = argv[++i];
        } else if (strcmp(argv[i], "--send-tx") == 0 && i + 3 < argc) {
            tx_target_id = atoi(argv[++i]);
            tx_amount = (uint64_t)strtoull(argv[++i], NULL, 10);
            tx_fee = (uint64_t)strtoull(argv[++i], NULL, 10);
            send_tx_flag = true;
        } else {
            usage(argv[0]);
            return EXIT_USAGE;
        }
    }
    if (!net_path || !cfg_path) {
        usage(argv[0]);
        return EXIT_USAGE;
    }

    log_init(-1);

    err[0] = '\0';
    rc = config_load_network(net_path, &net_cfg, err, sizeof err);
    if (rc == SC_OK)
        rc = config_check_topology(&net_cfg, TOPOLOGY_VALIDATORS,
                                   TOPOLOGY_NORMALS, err, sizeof err);
    if (rc == SC_OK)
        rc = config_load_node(cfg_path, &cfg, err, sizeof err);
    if (rc != SC_OK) {
        log_eventf(LOG_ERROR, "config", "config_error",
                   "code=%s detail=\"%s\"", sc_err_str(rc), err);
        return EXIT_FAILURE;
    }

    me = config_find_node(&net_cfg, cfg.node_id);
    if (!me) {
        log_eventf(LOG_ERROR, "config", "config_error",
                   "code=%s detail=\"node_id %d not in %s\"",
                   sc_err_str(SC_ERR_NOT_FOUND), cfg.node_id, net_path);
        return EXIT_FAILURE;
    }
    log_init(me->id);

    rc = crypto_load_privkey(&my_kp, cfg.key_path, err, sizeof err);
    if (rc != SC_OK) {
        log_eventf(LOG_ERROR, "crypto", "key_load_error",
                   "code=%s detail=\"%s\"", sc_err_str(rc), err);
        return EXIT_FAILURE;
    }

    if (me->has_pubkey) {
        uint8_t loaded_pub[SC_ED25519_PUBKEY_LEN];
        if (crypto_get_pubkey(my_kp, loaded_pub) != SC_OK ||
            memcmp(loaded_pub, me->pubkey, SC_ED25519_PUBKEY_LEN) != 0) {
            log_event(LOG_ERROR, "crypto", "key_mismatch_with_network_conf");
            crypto_keypair_free(my_kp);
            return EXIT_FAILURE;
        }
        log_event(LOG_INFO, "crypto", "key_verified_against_network_conf");
    }

    if (ledger_create(&ledger) != SC_OK) {
        crypto_keypair_free(my_kp);
        return EXIT_FAILURE;
    }

    if (cfg.data_dir[0] != '\0' && storage_state_exists(cfg.data_dir)) {
        if (storage_load_state(ledger, cfg.data_dir, err, sizeof(err)) == SC_OK) {
            log_eventf(LOG_INFO, "storage", "state_loaded", "dir=\"%s\"", cfg.data_dir);
        } else {
            log_eventf(LOG_WARN, "storage", "state_load_failed", "err=\"%s\"", err);
        }
    } else {
        for (size_t i = 0; i < net_cfg.count; i++) {
            if (net_cfg.nodes[i].has_pubkey) {
                ledger_set_account(ledger, net_cfg.nodes[i].pubkey, 1000000, 0);
            }
        }
        if (cfg.data_dir[0] != '\0') {
            storage_save_state(ledger, cfg.data_dir, err, sizeof(err));
        }
    }

    uint8_t state_hash[SC_SHA256_LEN];
    char state_hex[SC_SHA256_LEN * 2 + 1];
    ledger_compute_state_hash(ledger, state_hash);
    crypto_hex_encode(state_hash, SC_SHA256_LEN, state_hex);
    log_eventf(LOG_INFO, "ledger", "initial_state_root", "hash=%s", state_hex);

    if (mempool_create(&mempool) != SC_OK ||
        dag_create(&dag) != SC_OK ||
        consensus_create(&cons, &net_cfg, me->id, my_kp, dag, ledger, mempool, cfg.data_dir) != SC_OK) {
        ledger_free(ledger);
        crypto_keypair_free(my_kp);
        return EXIT_FAILURE;
    }

    install_signal_handlers();

    rc = open_listener(me, &listen_fd, err, sizeof err);
    if (rc != SC_OK) {
        log_eventf(LOG_ERROR, "net", "listen_error",
                   "code=%s detail=\"%s\"", sc_err_str(rc), err);
        consensus_free(cons);
        dag_free(dag);
        mempool_free(mempool);
        ledger_free(ledger);
        crypto_keypair_free(my_kp);
        return EXIT_FAILURE;
    }

    sc_node_ctx_t ctx = {
        .node_id = me->id,
        .net_cfg = net_cfg,
        .my_kp = my_kp,
        .net = NULL,
        .ledger = ledger,
        .mempool = mempool,
        .dag = dag,
        .consensus = cons,
        .current_round = 0
    };
    snprintf(ctx.data_dir, sizeof(ctx.data_dir), "%s", cfg.data_dir);

    rc = net_init(&net, &net_cfg, me, listen_fd, my_kp,
                  on_message, &ctx, err, sizeof err);
    if (rc != SC_OK) {
        log_eventf(LOG_ERROR, "net", "init_error",
                   "code=%s detail=\"%s\"", sc_err_str(rc), err);
        close(listen_fd);
        consensus_free(cons);
        dag_free(dag);
        mempool_free(mempool);
        ledger_free(ledger);
        crypto_keypair_free(my_kp);
        return EXIT_FAILURE;
    }
    ctx.net = net;

    log_eventf(LOG_INFO, "main", "started",
               "role=%s host=%s port=%u peers=%zu",
               role_str(me->role), me->host, (unsigned)me->port,
               net_cfg.count - 1);

    while (!g_stop_signal) {
        rc = net_poll_step(net, 100);
        if (rc != SC_OK && rc != SC_ERR_IO) {
            log_eventf(LOG_ERROR, "net", "poll_error", "code=%s", sc_err_str(rc));
            break;
        }

        propose_vertex_if_needed(&ctx);

        if (test_target_id >= 0 && !test_sent &&
            net_is_connected(net, test_target_id)) {
            size_t msg_len = strlen(test_msg);
            sc_err_t s_rc = net_send(net, test_target_id, MSG_TYPE_TEST,
                                     test_msg, msg_len);
            if (s_rc == SC_OK) {
                log_eventf(LOG_INFO, "net", "sent_test",
                           "to=%d len=%zu payload=\"%s\"",
                           test_target_id, msg_len, test_msg);
                test_sent = true;
            }
        }

        if (send_tx_flag && !tx_sent && net_is_connected(net, tx_target_id)) {
            const node_info_t *target = config_find_node(&net_cfg, tx_target_id);
            if (target && target->has_pubkey) {
                sc_account_t my_acc;
                uint64_t nonce = 0;
                if (ledger_get_account(ledger, me->pubkey, &my_acc) == SC_OK) {
                    nonce = my_acc.nonce;
                }

                sc_tx_t tx;
                if (tx_create(&tx, my_kp, target->pubkey, tx_amount, tx_fee, nonce) == SC_OK) {
                    uint8_t tx_buf[SC_TX_WIRE_LEN];
                    size_t written = 0;
                    tx_serialize(&tx, tx_buf, sizeof(tx_buf), &written);

                    bool added = false;
                    mempool_add(mempool, &tx, &added);

                    net_send(net, tx_target_id, MSG_TYPE_TX, tx_buf, written);
                    log_eventf(LOG_INFO, "tx", "sent_tx",
                               "to=%d amount=%llu fee=%llu nonce=%llu",
                               tx_target_id, (unsigned long long)tx_amount,
                               (unsigned long long)tx_fee, (unsigned long long)nonce);
                    tx_sent = true;
                }
            }
        }
    }

    log_eventf(LOG_INFO, "main", "shutdown", "signal=%d", (int)g_stop_signal);
    net_shutdown(net);
    close(listen_fd);
    consensus_free(cons);
    dag_free(dag);
    mempool_free(mempool);
    ledger_free(ledger);
    crypto_keypair_free(my_kp);
    return EXIT_SUCCESS;
}