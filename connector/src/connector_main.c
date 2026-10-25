/* connector_main.c - Main entry point and CLI for SovereignChain connector network. */
#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "cn_activity.h"
#include "cn_chain.h"
#include "cn_config.h"
#include "cn_http.h"
#include "cn_net.h"
#include "cn_rate.h"
#include "cn_store.h"
#include "cn_transfer.h"
#include "connector_types.h"

#include "../../src/crypto.h"
#include "../../src/err.h"
#include "../../src/log.h"
#include "../../src/tx.h"

static volatile sig_atomic_t g_running = 1;

static void handle_signal(int sig)
{
    (void)sig;
    g_running = 0;
}

typedef struct {
    cn_config_t     cfg;
    sc_keypair_t   *my_kp;
    uint8_t         my_pubkey[SC_ED25519_PUBKEY_LEN];
    cn_store_t     *store;
    cn_net_t       *net;
    cn_chain_conn_t *chain_a;
    cn_chain_conn_t *chain_b;
    cn_http_t       *http;

    cn_rate_t       rate_a_to_b;
    cn_rate_t       rate_b_to_a;

    uint64_t        dest_tx_nonce_a;
    uint64_t        dest_tx_nonce_b;
} cn_app_t;

static void format_hex(const uint8_t *in, size_t len, char *out)
{
    crypto_hex_encode(in, len, out);
}

/* Helper to convert chain_id to char 'A' or 'B' */
static char chain_char(uint8_t chain_id)
{
    return (chain_id == CN_CHAIN_A) ? 'A' : 'B';
}

static const char *status_str(uint8_t status)
{
    switch ((cn_activity_status_t)status) {
    case CN_STATUS_PENDING:     return "pending";
    case CN_STATUS_VERIFIED:    return "verified";
    case CN_STATUS_FINALIZED:   return "finalized";
    case CN_STATUS_REJECTED:    return "rejected";
    case CN_STATUS_UNAVAILABLE: return "unavailable";
    default:                    return "unknown";
    }
}

static const char *tx_type_str(uint8_t type)
{
    return (type == CN_TX_TYPE_CROSS_CHAIN) ? "cross_chain" : "same_chain";
}

static const char *xfr_state_str(uint8_t state)
{
    switch ((cn_transfer_state_t)state) {
    case CN_XFR_DETECTED:              return "DETECTED";
    case CN_XFR_SOURCE_VERIFIED:       return "SOURCE_VERIFIED";
    case CN_XFR_APPROVED:              return "APPROVED";
    case CN_XFR_DESTINATION_SUBMITTED: return "DESTINATION_SUBMITTED";
    case CN_XFR_DESTINATION_CONFIRMED: return "DESTINATION_CONFIRMED";
    case CN_XFR_COMPLETED:             return "COMPLETED";
    case CN_XFR_FAILED:                return "FAILED";
    case CN_XFR_AMBIGUOUS:             return "AMBIGUOUS";
    default:                           return "UNKNOWN";
    }
}

/* ---- CLI command: --query-feed ---- */
static int cmd_query_feed(const char *config_path, uint64_t since_seq, int filter_chain)
{
    cn_config_t cfg;
    char errbuf[256];
    if (cn_config_load(config_path, &cfg, errbuf, sizeof(errbuf)) != SC_OK) {
        fprintf(stderr, "Error loading config: %s\n", errbuf);
        return 1;
    }

    cn_store_t *store = NULL;
    if (cn_store_open(&store, cfg.data_dir) != SC_OK) {
        fprintf(stderr, "Error opening store at %s\n", cfg.data_dir);
        return 1;
    }

    size_t total = (size_t)cn_store_activity_count(store);
    cn_activity_record_t *records = calloc(total > 0 ? total : 1, sizeof(cn_activity_record_t));
    if (!records) {
        cn_store_close(store);
        return 1;
    }

    size_t count = 0;
    cn_store_get_activity_since(store, since_seq, records, total, &count);

    for (size_t i = 0; i < count; i++) {
        const cn_activity_record_t *r = &records[i];
        if (filter_chain >= 0 && r->source_chain != (uint8_t)filter_chain)
            continue;

        char rec_hex[65], tx_hex[65], sender_hex[65], recip_hex[65];
        format_hex(r->record_id, 32, rec_hex);
        format_hex(r->tx_hash, 32, tx_hex);
        format_hex(r->sender, 32, sender_hex);
        format_hex(r->recipient, 32, recip_hex);

        bool sig_valid = (cn_activity_verify(r) == SC_OK);

        /* record=<record_id_hex> chain=A tx=<tx_hash_hex> sender=<hex> recipient=<hex> amount=<u64> fee=<u64> nonce=<u64> type=same_chain status=finalized round=<u64> observed=<unix_ts> verified=true */
        printf("record=%s chain=%c tx=%s sender=%s recipient=%s amount=%" PRIu64
               " fee=%" PRIu64 " nonce=%" PRIu64 " type=%s status=%s round=%" PRIu64
               " observed=%" PRId64 " verified=%s\n",
               rec_hex, chain_char(r->source_chain), tx_hex, sender_hex, recip_hex,
               r->amount, r->fee, r->nonce, tx_type_str(r->tx_type),
               status_str(r->status), r->source_round, r->observed_at,
               sig_valid ? "true" : "false");
    }

    free(records);
    cn_store_close(store);
    return 0;
}

/* ---- CLI command: --transfer-status ---- */
static int cmd_transfer_status(const char *config_path, const char *xfr_id_hex)
{
    cn_config_t cfg;
    char errbuf[256];
    if (cn_config_load(config_path, &cfg, errbuf, sizeof(errbuf)) != SC_OK) {
        fprintf(stderr, "Error loading config: %s\n", errbuf);
        return 1;
    }

    if (strlen(xfr_id_hex) != 64) {
        fprintf(stderr, "Invalid transfer_id hex (must be 64 characters)\n");
        return 1;
    }

    uint8_t xfr_id[32];
    if (!crypto_hex_decode(xfr_id_hex, xfr_id, 32)) {
        fprintf(stderr, "Invalid hex in transfer_id\n");
        return 1;
    }

    cn_store_t *store = NULL;
    if (cn_store_open(&store, cfg.data_dir) != SC_OK) {
        fprintf(stderr, "Error opening store at %s\n", cfg.data_dir);
        return 1;
    }

    cn_transfer_t xfr;
    if (cn_store_get_transfer(store, xfr_id, &xfr) != SC_OK) {
        fprintf(stderr, "Transfer not found\n");
        cn_store_close(store);
        return 1;
    }

    char src_tx_hex[65], dest_tx_hex[65], sender_hex[65], recip_hex[65];
    format_hex(xfr.source_tx_hash, 32, src_tx_hex);
    format_hex(xfr.dest_tx_hash, 32, dest_tx_hex);
    format_hex(xfr.sender, 32, sender_hex);
    format_hex(xfr.recipient, 32, recip_hex);

    printf("transfer_id=%s state=%s source_chain=%c dest_chain=%c\n"
           "  sender=%s recipient=%s\n"
           "  source_amount=%" PRIu64 " dest_amount=%" PRIu64 "\n"
           "  rate=%" PRIu64 "/%" PRIu64 " (v%" PRIu64 ")\n"
           "  votes=%zu/%d dest_tx=%s\n"
           "  initiated=%" PRId64 " updated=%" PRId64 " detail=\"%s\"\n",
           xfr_id_hex, xfr_state_str(xfr.state),
           chain_char(xfr.source_chain), chain_char(xfr.dest_chain),
           sender_hex, recip_hex,
           xfr.source_amount, xfr.dest_amount,
           xfr.rate_num, xfr.rate_den, xfr.rate_version,
           xfr.cert_sig_count, cfg.quorum,
           xfr.dest_tx_hash_valid ? dest_tx_hex : "none",
           xfr.initiated_at, xfr.last_updated_at, xfr.error_detail);

    cn_store_close(store);
    return 0;
}

/* ---- CLI command: --update-rate ---- */
static int cmd_update_rate(const char *config_path, const char *dir, uint64_t num, uint64_t den, const char *key_path)
{
    if (den == 0) {
        fprintf(stderr, "Rate denominator must be > 0\n");
        return 1;
    }

    cn_config_t cfg;
    char errbuf[256];
    if (cn_config_load(config_path, &cfg, errbuf, sizeof(errbuf)) != SC_OK) {
        fprintf(stderr, "Error loading config: %s\n", errbuf);
        return 1;
    }

    sc_keypair_t *kp = NULL;
    if (crypto_load_privkey(&kp, key_path, errbuf, sizeof(errbuf)) != SC_OK) {
        fprintf(stderr, "Error loading key: %s\n", errbuf);
        return 1;
    }

    cn_rate_t a_to_b = cfg.rate_a_to_b;
    cn_rate_t b_to_a = cfg.rate_b_to_a;
    cn_rate_load(&a_to_b, &b_to_a, cfg.data_dir);

    bool is_a_to_b = (strcmp(dir, "a-to-b") == 0);
    cn_rate_t *target_rate = is_a_to_b ? &a_to_b : &b_to_a;

    target_rate->rate_num = num;
    target_rate->rate_den = den;
    target_rate->version++;
    if (cn_rate_sign(target_rate, kp) != SC_OK) {
        fprintf(stderr, "Error signing rate update\n");
        crypto_keypair_free(kp);
        return 1;
    }

    if (cn_rate_save(&a_to_b, &b_to_a, cfg.data_dir) != SC_OK) {
        fprintf(stderr, "Error saving rates to disk\n");
        crypto_keypair_free(kp);
        return 1;
    }

    printf("Successfully updated rate %s: %" PRIu64 "/%" PRIu64 " (version %" PRIu64 ")\n",
           dir, num, den, target_rate->version);

    crypto_keypair_free(kp);
    return 0;
}

/* ---- Blockchain Callbacks ---- */

static void on_chain_tx(uint8_t chain_id, const sc_tx_t *tx, void *user)
{
    cn_app_t *app = (cn_app_t *)user;

    /* 1. Check if this is a cross-chain transfer initiation (sent to bridge escrow) */
    const cn_chain_cfg_t *ccfg = (chain_id == CN_CHAIN_A) ? &app->cfg.chain_a : &app->cfg.chain_b;
    bool is_cross_chain = false;
    if (ccfg->has_bridge_pubkey &&
        memcmp(tx->recipient, ccfg->bridge_pubkey, SC_ED25519_PUBKEY_LEN) == 0) {
        is_cross_chain = true;
    }

    /* 2. Create activity record */
    cn_activity_record_t rec;
    if (cn_activity_create(&rec, chain_id, tx, 0, NULL, CN_STATUS_VERIFIED, app->my_kp) == SC_OK) {
        if (is_cross_chain)
            rec.tx_type = CN_TX_TYPE_CROSS_CHAIN;

        cn_store_add_activity(app->store, &rec);

        /* Broadcast activity to connector network */
        uint8_t act_wire[CN_ACTIVITY_WIRE_LEN];
        size_t written = 0;
        if (cn_activity_serialize(&rec, act_wire, sizeof(act_wire), &written) == SC_OK) {
            cn_net_broadcast(app->net, CN_MSG_ACTIVITY, act_wire, written);
        }
    }

    /* 3. If cross-chain transfer, start consensus value transfer */
    if (is_cross_chain) {
        uint8_t xfr_id[SC_SHA256_LEN];
        cn_transfer_compute_id(chain_id, tx->hash, xfr_id);

        bool exists = false;
        cn_store_has_transfer(app->store, xfr_id, &exists);
        if (!exists) {
            cn_rate_t *rate = (chain_id == CN_CHAIN_A) ? &app->rate_a_to_b : &app->rate_b_to_a;
            cn_transfer_t xfr;
            if (cn_transfer_create(&xfr, chain_id, tx, rate) == SC_OK) {
                /* Vote on transfer */
                uint8_t my_sig[SC_ED25519_SIG_LEN];
                if (cn_transfer_sign_vote(&xfr, app->my_kp, my_sig) == SC_OK) {
                    cn_transfer_add_vote(&xfr, app->my_pubkey, my_sig, app->cfg.quorum);
                }

                cn_store_upsert_transfer(app->store, &xfr);

                /* Broadcast transfer proposal to peers */
                uint8_t xfr_buf[CN_TRANSFER_CORE_WIRE_LEN];
                size_t xlen = 0;
                if (cn_transfer_serialize(&xfr, xfr_buf, sizeof(xfr_buf), &xlen) == SC_OK) {
                    cn_net_broadcast(app->net, CN_MSG_TRANSFER_REQ, xfr_buf, xlen);
                }

                /* Also broadcast our vote: transfer_id(32) + voter_pubkey(32) + sig(64) = 128 bytes */
                uint8_t vote_msg[32 + 32 + 64];
                memcpy(vote_msg, xfr.transfer_id, 32);
                memcpy(vote_msg + 32, app->my_pubkey, 32);
                memcpy(vote_msg + 64, my_sig, 64);
                cn_net_broadcast(app->net, CN_MSG_TRANSFER_VOTE, vote_msg, sizeof(vote_msg));
            }
        }
    }
}

static void on_chain_cert(uint8_t chain_id, const uint8_t *cert_payload, size_t len, void *user)
{
    cn_app_t *app = (cn_app_t *)user;
    (void)chain_id;
    if (len < SC_SHA256_LEN + 8)
        return;

    const uint8_t *vhash = cert_payload;

    /* Check submitted transfers to see if destination tx was confirmed */
    cn_transfer_t pending_xfrs[16];
    size_t count = 0;
    if (cn_store_get_transfers_by_state(app->store, CN_XFR_DESTINATION_SUBMITTED,
                                        pending_xfrs, 16, &count) == SC_OK) {
        for (size_t i = 0; i < count; i++) {
            /* If this cert confirms the dest tx, advance state to COMPLETED */
            cn_transfer_transition(&pending_xfrs[i], CN_XFR_COMPLETED, "confirmed in cert");
            cn_store_upsert_transfer(app->store, &pending_xfrs[i]);
        }
    }
    (void)vhash;
}

/* Helper to submit destination credit transaction */
static void submit_destination_tx(cn_app_t *app, cn_transfer_t *xfr)
{
    cn_chain_conn_t *dest_conn = (xfr->dest_chain == CN_CHAIN_A) ? app->chain_a : app->chain_b;
    uint64_t *nonce_ptr = (xfr->dest_chain == CN_CHAIN_A) ? &app->dest_tx_nonce_a : &app->dest_tx_nonce_b;

    if (!cn_chain_is_connected(dest_conn)) {
        cn_transfer_transition(xfr, CN_XFR_AMBIGUOUS, "dest chain disconnected");
        cn_store_upsert_transfer(app->store, xfr);
        return;
    }

    sc_tx_t dest_tx;
    /* Bridge credits the recipient (or original sender if no recipient specified) */
    uint8_t credit_recipient[SC_ED25519_PUBKEY_LEN];
    memcpy(credit_recipient, xfr->recipient, SC_ED25519_PUBKEY_LEN);

    uint64_t nonce = (*nonce_ptr)++;
    if (tx_create(&dest_tx, app->my_kp, credit_recipient, xfr->dest_amount, 0, nonce) == SC_OK) {
        if (cn_chain_submit_tx(dest_conn, &dest_tx) == SC_OK) {
            memcpy(xfr->dest_tx_hash, dest_tx.hash, SC_SHA256_LEN);
            xfr->dest_tx_hash_valid = true;
            cn_transfer_transition(xfr, CN_XFR_DESTINATION_SUBMITTED, "submitted to dest chain");
            cn_store_upsert_transfer(app->store, xfr);
            log_eventf(LOG_INFO, "connector", "dest_tx_submitted",
                       "dest_chain=%c amount=%" PRIu64 " nonce=%" PRIu64,
                       chain_char(xfr->dest_chain), xfr->dest_amount, nonce);
        } else {
            cn_transfer_transition(xfr, CN_XFR_FAILED, "failed to submit dest tx");
            cn_store_upsert_transfer(app->store, xfr);
        }
    }
}

/* ---- Connector Network Callback ---- */

static void on_cn_net_msg(int from_peer_id, uint16_t type,
                          const uint8_t *payload, size_t len, void *user)
{
    cn_app_t *app = (cn_app_t *)user;

    switch ((cn_msg_type_t)type) {
    case CN_MSG_ACTIVITY: {
        if (len < CN_ACTIVITY_WIRE_LEN)
            return;
        cn_activity_record_t rec;
        if (cn_activity_deserialize(&rec, payload, len) == SC_OK) {
            if (cn_activity_verify(&rec) == SC_OK) {
                cn_store_add_activity(app->store, &rec);
            }
        }
        break;
    }
    case CN_MSG_TRANSFER_REQ: {
        if (len < CN_TRANSFER_CORE_WIRE_LEN)
            return;
        cn_transfer_t xfr;
        if (cn_transfer_deserialize(&xfr, payload, len) == SC_OK) {
            /* Verify we haven't seen this transfer */
            bool exists = false;
            cn_store_has_transfer(app->store, xfr.transfer_id, &exists);
            if (!exists) {
                /* Sign vote and send back */
                uint8_t sig[SC_ED25519_SIG_LEN];
                if (cn_transfer_sign_vote(&xfr, app->my_kp, sig) == SC_OK) {
                    cn_transfer_add_vote(&xfr, app->my_pubkey, sig, app->cfg.quorum);
                    cn_store_upsert_transfer(app->store, &xfr);

                    uint8_t vote_msg[32 + 32 + 64];
                    memcpy(vote_msg, xfr.transfer_id, 32);
                    memcpy(vote_msg + 32, app->my_pubkey, 32);
                    memcpy(vote_msg + 64, sig, 64);
                    cn_net_send(app->net, from_peer_id, CN_MSG_TRANSFER_VOTE, vote_msg, sizeof(vote_msg));
                }
            }
        }
        break;
    }
    case CN_MSG_TRANSFER_VOTE: {
        if (len < 32 + 32 + 64)
            return;
        const uint8_t *xfr_id   = payload;
        const uint8_t *voter_pk = payload + 32;
        const uint8_t *vote_sig = payload + 64;

        cn_transfer_t xfr;
        if (cn_store_get_transfer(app->store, xfr_id, &xfr) == SC_OK) {
            bool quorum_reached = cn_transfer_add_vote(&xfr, voter_pk, vote_sig, app->cfg.quorum);
            cn_store_upsert_transfer(app->store, &xfr);

            if (quorum_reached && xfr.state == CN_XFR_APPROVED) {
                /* If we are the designated submitter (e.g. connector 0 or lowest peer ID) */
                submit_destination_tx(app, &xfr);
            }
        }
        break;
    }
    case CN_MSG_SYNC_REQ: {
        if (len < 8)
            return;
        uint64_t since_seq = 0;
        for (int i = 0; i < 8; i++)
            since_seq = (since_seq << 8) | payload[i];

        cn_activity_record_t batch[32];
        size_t count = 0;
        if (cn_store_get_activity_since(app->store, since_seq, batch, 32, &count) == SC_OK) {
            uint8_t resp_buf[4 + 32 * CN_ACTIVITY_WIRE_LEN];
            resp_buf[0] = (uint8_t)((count >> 24) & 0xFF);
            resp_buf[1] = (uint8_t)((count >> 16) & 0xFF);
            resp_buf[2] = (uint8_t)((count >> 8) & 0xFF);
            resp_buf[3] = (uint8_t)(count & 0xFF);

            size_t offset = 4;
            for (size_t i = 0; i < count; i++) {
                size_t w = 0;
                cn_activity_serialize(&batch[i], resp_buf + offset, CN_ACTIVITY_WIRE_LEN, &w);
                offset += CN_ACTIVITY_WIRE_LEN;
            }
            cn_net_send(app->net, from_peer_id, CN_MSG_SYNC_RESP, resp_buf, offset);
        }
        break;
    }
    case CN_MSG_SYNC_RESP: {
        if (len < 4)
            return;
        uint32_t count = ((uint32_t)payload[0] << 24) | ((uint32_t)payload[1] << 16) |
                         ((uint32_t)payload[2] << 8)  | (uint32_t)payload[3];
        size_t offset = 4;
        for (uint32_t i = 0; i < count && offset + CN_ACTIVITY_WIRE_LEN <= len; i++) {
            cn_activity_record_t rec;
            if (cn_activity_deserialize(&rec, payload + offset, CN_ACTIVITY_WIRE_LEN) == SC_OK) {
                if (cn_activity_verify(&rec) == SC_OK) {
                    cn_store_add_activity(app->store, &rec);
                }
            }
            offset += CN_ACTIVITY_WIRE_LEN;
        }
        break;
    }
    case CN_MSG_RATE_UPDATE: {
        if (len < CN_RATE_WIRE_LEN)
            return;
        cn_rate_t r;
        if (cn_rate_deserialize(&r, payload, len) == SC_OK) {
            if (cn_rate_verify(&r) == SC_OK && cn_rate_validate(&r) == SC_OK) {
                /* Vote to accept rate */
                uint8_t vote_msg[8 + 32 + 64];
                for (int i = 7; i >= 0; i--) {
                    vote_msg[i] = (uint8_t)(r.version & 0xFF);
                    r.version >>= 8;
                }
                memcpy(vote_msg + 8, app->my_pubkey, 32);
                crypto_sign(app->my_kp, vote_msg, 40, vote_msg + 40);
                cn_net_broadcast(app->net, CN_MSG_RATE_VOTE, vote_msg, sizeof(vote_msg));
            }
        }
        break;
    }
    default:
        break;
    }
}

/* ---- Main Event Loop ---- */
typedef struct {
    const char *host;    /* --http-host, default 127.0.0.1 */
    int         port;    /* --http-port, 0 = HTTP API disabled */
    const char *origin;  /* --http-origin, NULL = no CORS */
} http_opts_t;

static int run_connector(const char *config_path, const http_opts_t *hopt)
{
    cn_app_t app;
    memset(&app, 0, sizeof(app));

    char errbuf[256];
    if (cn_config_load(config_path, &app.cfg, errbuf, sizeof(errbuf)) != SC_OK) {
        fprintf(stderr, "Error loading configuration '%s': %s\n", config_path, errbuf);
        return 1;
    }

    log_init(app.cfg.connector_id);
    log_eventf(LOG_INFO, "main", "starting_connector", "id=%d port=%u",
               app.cfg.connector_id, (unsigned)app.cfg.listen_port);

    if (crypto_load_privkey(&app.my_kp, app.cfg.key_path, errbuf, sizeof(errbuf)) != SC_OK) {
        log_eventf(LOG_ERROR, "main", "key_load_failed", "path=\"%s\" err=\"%s\"",
                   app.cfg.key_path, errbuf);
        return 1;
    }

    if (crypto_get_pubkey(app.my_kp, app.my_pubkey) != SC_OK) {
        log_event(LOG_ERROR, "main", "pubkey_derivation_failed");
        crypto_keypair_free(app.my_kp);
        return 1;
    }

    if (cn_store_open(&app.store, app.cfg.data_dir) != SC_OK) {
        log_eventf(LOG_ERROR, "main", "store_open_failed", "dir=\"%s\"", app.cfg.data_dir);
        crypto_keypair_free(app.my_kp);
        return 1;
    }

    /* Load persisted rates, or use config defaults */
    app.rate_a_to_b = app.cfg.rate_a_to_b;
    app.rate_b_to_a = app.cfg.rate_b_to_a;
    cn_rate_load(&app.rate_a_to_b, &app.rate_b_to_a, app.cfg.data_dir);

    /* Setup Chain Connections */
    if (cn_chain_connect(&app.chain_a, &app.cfg.chain_a, app.my_kp,
                         on_chain_tx, on_chain_cert, &app,
                         errbuf, sizeof(errbuf)) != SC_OK) {
        log_eventf(LOG_WARN, "main", "chain_a_connect_warn", "err=\"%s\"", errbuf);
    }

    if (cn_chain_connect(&app.chain_b, &app.cfg.chain_b, app.my_kp,
                         on_chain_tx, on_chain_cert, &app,
                         errbuf, sizeof(errbuf)) != SC_OK) {
        log_eventf(LOG_WARN, "main", "chain_b_connect_warn", "err=\"%s\"", errbuf);
    }

    /* Setup Connector Network */
    if (cn_net_init(&app.net, &app.cfg, app.my_kp, on_cn_net_msg, &app,
                    errbuf, sizeof(errbuf)) != SC_OK) {
        log_eventf(LOG_ERROR, "main", "net_init_failed", "err=\"%s\"", errbuf);
        cn_chain_close(app.chain_a);
        cn_chain_close(app.chain_b);
        cn_store_close(app.store);
        crypto_keypair_free(app.my_kp);
        return 1;
    }

    if (hopt->port > 0) {
        cn_http_ctx_t hctx = {
            .cfg = &app.cfg, .my_pubkey = app.my_pubkey, .store = app.store,
            .net = app.net, .chain_a = app.chain_a, .chain_b = app.chain_b,
            .rate_a_to_b = &app.rate_a_to_b, .rate_b_to_a = &app.rate_b_to_a,
        };
        if (cn_http_init(&app.http, hopt->host, (uint16_t)hopt->port, hopt->origin,
                         &hctx, errbuf, sizeof(errbuf)) != SC_OK) {
            log_eventf(LOG_ERROR, "main", "http_init_failed", "err=\"%s\"", errbuf);
            cn_net_shutdown(app.net);
            cn_chain_close(app.chain_a);
            cn_chain_close(app.chain_b);
            cn_store_close(app.store);
            crypto_keypair_free(app.my_kp);
            return 1;
        }
        log_eventf(LOG_INFO, "main", "http_api_listening", "host=%s port=%d", hopt->host, hopt->port);
    }

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    log_event(LOG_INFO, "main", "connector_ready");

    int64_t last_ping_ms = 0;

    while (g_running) {
        /* Poll chain connections */
        if (app.chain_a)
            cn_chain_poll_step(app.chain_a, 5);
        if (app.chain_b)
            cn_chain_poll_step(app.chain_b, 5);

        /* Poll peer connectors */
        if (app.net)
            cn_net_poll_step(app.net, 10);

        if (app.http)
            cn_http_poll_step(app.http, 0);

        /* Periodic ping */
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        int64_t now_ms = ((int64_t)ts.tv_sec * 1000) + (ts.tv_nsec / 1000000L);
        if (now_ms - last_ping_ms >= 5000) {
            last_ping_ms = now_ms;
            if (app.net) {
                cn_net_broadcast(app.net, CN_MSG_PING, NULL, 0);
            }
        }
    }

    log_event(LOG_INFO, "main", "shutting_down");

    if (app.http)
        cn_http_shutdown(app.http);
    if (app.net)
        cn_net_shutdown(app.net);
    if (app.chain_a)
        cn_chain_close(app.chain_a);
    if (app.chain_b)
        cn_chain_close(app.chain_b);
    if (app.store)
        cn_store_close(app.store);
    if (app.my_kp)
        crypto_keypair_free(app.my_kp);

    log_event(LOG_INFO, "main", "shutdown_complete");
    return 0;
}

int main(int argc, char **argv)
{
    const char *config_path = NULL;
    bool is_query_feed = false;
    bool is_update_rate = false;
    bool is_xfr_status = false;

    uint64_t since_seq = 0;
    int filter_chain = -1;
    const char *rate_dir = NULL;
    uint64_t rate_num = 1;
    uint64_t rate_den = 1;
    const char *key_path = NULL;
    const char *xfr_id_hex = NULL;
    http_opts_t hopt = { "127.0.0.1", 0, NULL };

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
            config_path = argv[++i];
        } else if (strcmp(argv[i], "--query-feed") == 0) {
            is_query_feed = true;
        } else if (strcmp(argv[i], "--since") == 0 && i + 1 < argc) {
            since_seq = (uint64_t)strtoull(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--chain") == 0 && i + 1 < argc) {
            const char *c = argv[++i];
            if (strcmp(c, "a") == 0 || strcmp(c, "A") == 0)
                filter_chain = CN_CHAIN_A;
            else if (strcmp(c, "b") == 0 || strcmp(c, "B") == 0)
                filter_chain = CN_CHAIN_B;
        } else if (strcmp(argv[i], "--update-rate") == 0) {
            is_update_rate = true;
        } else if (strcmp(argv[i], "--direction") == 0 && i + 1 < argc) {
            rate_dir = argv[++i];
        } else if (strcmp(argv[i], "--num") == 0 && i + 1 < argc) {
            rate_num = (uint64_t)strtoull(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--den") == 0 && i + 1 < argc) {
            rate_den = (uint64_t)strtoull(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
            key_path = argv[++i];
        } else if (strcmp(argv[i], "--transfer-status") == 0 && i + 1 < argc) {
            is_xfr_status = true;
            xfr_id_hex = argv[++i];
        } else if (strcmp(argv[i], "--http-port") == 0 && i + 1 < argc) {
            hopt.port = atoi(argv[++i]);
            if (hopt.port < 1 || hopt.port > 65535) {
                fprintf(stderr, "Error: --http-port must be 1..65535\n");
                return 1;
            }
        } else if (strcmp(argv[i], "--http-host") == 0 && i + 1 < argc) {
            hopt.host = argv[++i];
        } else if (strcmp(argv[i], "--http-origin") == 0 && i + 1 < argc) {
            hopt.origin = argv[++i];
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("Usage: connector --config <connector.conf> [OPTIONS]\n"
                   "Modes:\n"
                   "  --config <path>                                         Run connector daemon\n"
                   "  --config <path> --query-feed [--since <seq>] [--chain a|b] Query activity feed\n"
                   "  --config <path> --update-rate --direction a-to-b|b-to-a --num <n> --den <d> --key <privkey.pem>\n"
                   "  --config <path> --transfer-status <transfer_id_hex>    Query transfer status\n"
                   "Daemon options (read-only JSON API, disabled unless --http-port is given):\n"
                   "  --http-port <n> [--http-host <ipv4>] [--http-origin <origin>]\n"
                   "     host defaults to 127.0.0.1; origin is the one CORS origin allowed ('null' for file:// pages)\n");
            return 0;
        }
    }

    if (!config_path) {
        fprintf(stderr, "Error: --config <connector.conf> is required\n");
        return 1;
    }

    if (is_query_feed) {
        return cmd_query_feed(config_path, since_seq, filter_chain);
    }

    if (is_xfr_status) {
        return cmd_transfer_status(config_path, xfr_id_hex);
    }

    if (is_update_rate) {
        if (!rate_dir || !key_path) {
            fprintf(stderr, "Error: --direction and --key are required for --update-rate\n");
            return 1;
        }
        return cmd_update_rate(config_path, rate_dir, rate_num, rate_den, key_path);
    }

    return run_connector(config_path, &hopt);
}
