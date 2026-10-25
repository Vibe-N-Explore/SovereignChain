/* cn_http.c - Read-only HTTP/1.1 JSON API (see cn_http.h). */
#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "cn_activity.h"
#include "cn_http.h"
#include "cn_rate.h"
#include "../../src/log.h"

#define HTTP_MAX_CLIENTS 16
#define HTTP_MAX_REQ     8192
#define HTTP_IDLE_MS     5000
#define HTTP_MAX_BODY    (2u * 1024u * 1024u)
#define LIMIT_DEFAULT    50
#define LIMIT_MAX        200

typedef struct {
    int      fd;
    char     in[HTTP_MAX_REQ + 1];
    size_t   in_len;
    char    *out;
    size_t   out_len, out_off;
    int64_t  deadline_ms;
    bool     responding;
} client_t;

struct cn_http {
    int          lfd;
    bool         loopback;
    char         origin[128];
    bool         has_origin;
    cn_http_ctx_t ctx;
    int64_t      started_s;
    client_t     clients[HTTP_MAX_CLIENTS];
};

/* ---------- time ---------- */
static int64_t mono_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000L;
}

/* ---------- growable JSON buffer ---------- */
typedef struct { char *p; size_t len, cap; bool oom; } sb_t;

static void sb_put(sb_t *b, const char *s, size_t n)
{
    if (b->oom) return;
    if (b->len + n + 1 > HTTP_MAX_BODY) { b->oom = true; return; }
    if (b->len + n + 1 > b->cap) {
        size_t nc = b->cap ? b->cap : 1024;
        while (nc < b->len + n + 1) nc *= 2;
        char *np = realloc(b->p, nc);
        if (!np) { b->oom = true; return; }
        b->p = np; b->cap = nc;
    }
    memcpy(b->p + b->len, s, n);
    b->len += n;
    b->p[b->len] = '\0';
}
static void sb_raw(sb_t *b, const char *s) { sb_put(b, s, strlen(s)); }

static void sb_printf(sb_t *b, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void sb_printf(sb_t *b, const char *fmt, ...)
{
    char tmp[512];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= sizeof(tmp)) { b->oom = true; return; }
    sb_put(b, tmp, (size_t)n);
}

/* JSON string with escaping; control and non-ASCII bytes are \u-escaped. */
static void sb_str(sb_t *b, const char *s)
{
    sb_raw(b, "\"");
    for (const unsigned char *c = (const unsigned char *)s; *c; c++) {
        if (*c == '"' || *c == '\\') { char t[3] = {'\\', (char)*c, 0}; sb_raw(b, t); }
        else if (*c < 0x20 || *c >= 0x7f) sb_printf(b, "\\u%04x", *c);
        else sb_put(b, (const char *)c, 1);
    }
    sb_raw(b, "\"");
}
static void sb_hex(sb_t *b, const uint8_t *d, size_t n)
{
    char hex[2 * 64 + 1];
    if (n > 64) { b->oom = true; return; }
    crypto_hex_encode(d, n, hex);
    sb_printf(b, "\"%s\"", hex);
}
static void sb_u64(sb_t *b, uint64_t v) { sb_printf(b, "\"%" PRIu64 "\"", v); }
static void sb_bool(sb_t *b, bool v) { sb_raw(b, v ? "true" : "false"); }

static bool all_zero(const uint8_t *d, size_t n)
{
    for (size_t i = 0; i < n; i++) if (d[i]) return false;
    return true;
}
static char chain_ch(uint8_t c) { return c == CN_CHAIN_A ? 'A' : 'B'; }

static const char *act_status(uint8_t s)
{
    switch ((cn_activity_status_t)s) {
    case CN_STATUS_PENDING: return "pending";
    case CN_STATUS_VERIFIED: return "verified";
    case CN_STATUS_FINALIZED: return "finalized";
    case CN_STATUS_REJECTED: return "rejected";
    case CN_STATUS_UNAVAILABLE: return "unavailable";
    }
    return "unknown";
}
static const char *xfr_state(uint8_t s)
{
    switch ((cn_transfer_state_t)s) {
    case CN_XFR_DETECTED: return "DETECTED";
    case CN_XFR_SOURCE_VERIFIED: return "SOURCE_VERIFIED";
    case CN_XFR_APPROVED: return "APPROVED";
    case CN_XFR_DESTINATION_SUBMITTED: return "DESTINATION_SUBMITTED";
    case CN_XFR_DESTINATION_CONFIRMED: return "DESTINATION_CONFIRMED";
    case CN_XFR_COMPLETED: return "COMPLETED";
    case CN_XFR_FAILED: return "FAILED";
    case CN_XFR_AMBIGUOUS: return "AMBIGUOUS";
    }
    return "UNKNOWN";
}
static const char *tx_type(uint8_t t) { return t == CN_TX_TYPE_CROSS_CHAIN ? "cross_chain" : "same_chain"; }

/* ---------- query string ---------- */
typedef struct { char key[24]; char val[80]; } qp_t;
#define MAX_QP 8

/* Accepts only [A-Za-z0-9_.-] in values; anything else is a 400. */
static bool parse_query(const char *q, qp_t *out, size_t *n)
{
    *n = 0;
    while (q && *q) {
        if (*n >= MAX_QP) return false;
        const char *eq = strchr(q, '='), *amp = strchr(q, '&');
        if (!eq || (amp && eq > amp)) return false;
        size_t kl = (size_t)(eq - q), vl = amp ? (size_t)(amp - eq - 1) : strlen(eq + 1);
        if (kl == 0 || kl >= sizeof(out->key) || vl >= sizeof(out->val)) return false;
        memcpy(out[*n].key, q, kl); out[*n].key[kl] = 0;
        memcpy(out[*n].val, eq + 1, vl); out[*n].val[vl] = 0;
        for (size_t i = 0; i < vl; i++) {
            char c = out[*n].val[i];
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || c == '-' || c == '.'))
                return false;
        }
        (*n)++;
        q = amp ? amp + 1 : NULL;
    }
    return true;
}
static const char *qget(const qp_t *q, size_t n, const char *k)
{
    for (size_t i = 0; i < n; i++) if (strcmp(q[i].key, k) == 0) return q[i].val;
    return NULL;
}
static bool parse_u64(const char *s, uint64_t *out)
{
    if (!s || !*s || strlen(s) > 20) return false;
    uint64_t v = 0;
    for (; *s; s++) {
        if (*s < '0' || *s > '9') return false;
        uint64_t d = (uint64_t)(*s - '0');
        if (v > (UINT64_MAX - d) / 10) return false;
        v = v * 10 + d;
    }
    *out = v;
    return true;
}
static bool known_key(const qp_t *q, size_t n, const char *const *allowed)
{
    for (size_t i = 0; i < n; i++) {
        bool ok = false;
        for (const char *const *a = allowed; *a; a++) if (strcmp(q[i].key, *a) == 0) ok = true;
        if (!ok) return false;
    }
    return true;
}

/* ---------- response plumbing ---------- */
typedef struct { int status; const char *reason; sb_t body; } resp_t;

static void err_body(resp_t *r, int status, const char *reason, const char *code, const char *msg)
{
    r->status = status; r->reason = reason;
    r->body.len = 0;
    if (r->body.p) r->body.p[0] = 0;
    sb_printf(&r->body, "{\"error\":{\"code\":\"%s\",\"message\":", code);
    sb_str(&r->body, msg);
    sb_raw(&r->body, "}}");
}

/* ---------- endpoints ---------- */
static void ep_status(cn_http_t *h, resp_t *r)
{
    const cn_http_ctx_t *c = &h->ctx; sb_t *b = &r->body;
    int64_t now = (int64_t)time(NULL);
    sb_printf(b, "{\"service\":\"sovereignchain-connector\",\"api_version\":1,\"server_time\":%" PRId64
                 ",\"uptime_seconds\":%" PRId64 ",", now, now - h->started_s);
    sb_printf(b, "\"connector\":{\"id\":%d,\"public_key\":", c->cfg->connector_id);
    sb_hex(b, c->my_pubkey, SC_ED25519_PUBKEY_LEN);
    sb_printf(b, ",\"quorum\":%d},\"chains\":[", c->cfg->quorum);
    for (int i = 0; i < 2; i++) {
        const cn_chain_cfg_t *cc = i ? &c->cfg->chain_b : &c->cfg->chain_a;
        cn_chain_conn_t *cn = i ? c->chain_b : c->chain_a;
        if (i) sb_raw(b, ",");
        sb_printf(b, "{\"id\":\"%c\",\"endpoint_host\":", i ? 'B' : 'A');
        sb_str(b, cc->host);
        sb_printf(b, ",\"endpoint_port\":%u,\"connector_node_id\":%d,\"bridge_pubkey\":", (unsigned)cc->port, cc->our_node_id);
        if (cc->has_bridge_pubkey) sb_hex(b, cc->bridge_pubkey, SC_ED25519_PUBKEY_LEN); else sb_raw(b, "null");
        sb_raw(b, ",\"connected\":"); sb_bool(b, cn && cn_chain_is_connected(cn)); sb_raw(b, "}");
    }
    size_t conn = c->net ? cn_net_connected_count(c->net) : 0;
    sb_printf(b, "],\"peers\":{\"configured\":%zu,\"connected\":%zu,\"list\":[", c->cfg->peer_count, conn);
    for (size_t i = 0; i < c->cfg->peer_count; i++) {
        const cn_peer_info_t *p = &c->cfg->peers[i];
        bool self = p->id == c->cfg->connector_id;
        if (i) sb_raw(b, ",");
        sb_printf(b, "{\"id\":%d,\"host\":", p->id); sb_str(b, p->host);
        sb_printf(b, ",\"port\":%u,\"self\":", (unsigned)p->port); sb_bool(b, self);
        sb_raw(b, ",\"connected\":");
        if (self) sb_raw(b, "null"); else sb_bool(b, c->net && cn_net_is_connected(c->net, p->id));
        sb_raw(b, "}");
    }
    size_t total = cn_store_transfer_count(c->store), by[8] = {0};
    cn_transfer_t *t = malloc(sizeof(*t));
    if (!t) { err_body(r, 500, "Internal Server Error", "internal", "out of memory"); return; }
    for (size_t i = 0; i < total; i++)
        if (cn_store_get_transfer_at(c->store, i, t) == SC_OK && t->state < 8) by[t->state]++;
    free(t);
    sb_raw(b, "]},\"store\":{\"activity_count\":"); sb_u64(b, cn_store_activity_count(c->store));
    sb_printf(b, ",\"transfers\":{\"total\":%zu,\"by_state\":{", total);
    for (int s = 0; s < 8; s++) sb_printf(b, "%s\"%s\":%zu", s ? "," : "", xfr_state((uint8_t)s), by[s]);
    sb_raw(b, "}}}}");
}

static void ep_topology(cn_http_t *h, resp_t *r)
{
    const cn_http_ctx_t *c = &h->ctx; sb_t *b = &r->body;
    sb_raw(b, "{\"nodes\":[");
    sb_printf(b, "{\"id\":\"connector-%d\",\"kind\":\"connector\",\"self\":true,\"host\":", c->cfg->connector_id);
    sb_str(b, c->cfg->listen_host);
    sb_printf(b, ",\"port\":%u,\"state\":\"serving\",\"evidence\":\"this process answered the request\"}", (unsigned)c->cfg->listen_port);
    for (size_t i = 0; i < c->cfg->peer_count; i++) {
        const cn_peer_info_t *p = &c->cfg->peers[i];
        if (p->id == c->cfg->connector_id) continue;
        bool up = c->net && cn_net_is_connected(c->net, p->id);
        sb_printf(b, ",{\"id\":\"connector-%d\",\"kind\":\"connector\",\"self\":false,\"host\":", p->id); sb_str(b, p->host);
        sb_printf(b, ",\"port\":%u,\"state\":\"%s\",\"evidence\":\"authenticated link from this connector\"}",
                  (unsigned)p->port, up ? "connected" : "not_connected");
    }
    for (int i = 0; i < 2; i++) {
        const cn_chain_cfg_t *cc = i ? &c->cfg->chain_b : &c->cfg->chain_a;
        cn_chain_conn_t *cn = i ? c->chain_b : c->chain_a;
        sb_printf(b, ",{\"id\":\"chain-%c-endpoint\",\"kind\":\"chain_node\",\"chain\":\"%c\",\"source\":\"configured\",\"node_id\":%d,\"host\":",
                  i ? 'B' : 'A', i ? 'B' : 'A', cc->our_node_id);
        sb_str(b, cc->host);
        sb_printf(b, ",\"port\":%u,\"state\":\"%s\"}", (unsigned)cc->port,
                  (cn && cn_chain_is_connected(cn)) ? "connected" : "not_connected");
    }
    sb_raw(b, "],\"links\":[");
    bool first = true;
    for (size_t i = 0; i < c->cfg->peer_count; i++) {
        const cn_peer_info_t *p = &c->cfg->peers[i];
        if (p->id == c->cfg->connector_id) continue;
        sb_printf(b, "%s{\"from\":\"connector-%d\",\"to\":\"connector-%d\",\"live\":", first ? "" : ",", c->cfg->connector_id, p->id);
        sb_bool(b, c->net && cn_net_is_connected(c->net, p->id)); sb_raw(b, "}");
        first = false;
    }
    for (int i = 0; i < 2; i++) {
        cn_chain_conn_t *cn = i ? c->chain_b : c->chain_a;
        sb_printf(b, "%s{\"from\":\"connector-%d\",\"to\":\"chain-%c-endpoint\",\"live\":", first ? "" : ",", c->cfg->connector_id, i ? 'B' : 'A');
        sb_bool(b, cn && cn_chain_is_connected(cn)); sb_raw(b, "}");
        first = false;
    }
    sb_raw(b, "],\"not_exposed\":[\"chain node membership and roles beyond the single endpoint each connector uses\","
              "\"chain consensus state\",\"connections of other connectors to each other\"]}");
}

static void write_activity(sb_t *b, const cn_activity_record_t *a, uint64_t seq)
{
    bool vertex = !all_zero(a->source_vertex_hash, SC_SHA256_LEN);
    sb_raw(b, "{\"seq\":"); sb_u64(b, seq);
    sb_raw(b, ",\"record_id\":"); sb_hex(b, a->record_id, 32);
    sb_printf(b, ",\"source_chain\":\"%c\",\"tx_hash\":", chain_ch(a->source_chain)); sb_hex(b, a->tx_hash, 32);
    sb_raw(b, ",\"sender\":"); sb_hex(b, a->sender, 32);
    sb_raw(b, ",\"recipient\":"); sb_hex(b, a->recipient, 32);
    sb_raw(b, ",\"amount\":"); sb_u64(b, a->amount);
    sb_raw(b, ",\"fee\":"); sb_u64(b, a->fee);
    sb_raw(b, ",\"nonce\":"); sb_u64(b, a->nonce);
    sb_printf(b, ",\"type\":\"%s\",\"status\":\"%s\",\"source_round\":", tx_type(a->tx_type), act_status(a->status));
    if (vertex) sb_u64(b, a->source_round); else sb_raw(b, "null");
    sb_raw(b, ",\"source_vertex_hash\":"); if (vertex) sb_hex(b, a->source_vertex_hash, 32); else sb_raw(b, "null");
    sb_printf(b, ",\"observed_at\":%" PRId64 ",\"reporter_pubkey\":", a->observed_at); sb_hex(b, a->reporter_pubkey, 32);
    /* Verifies the reporting connector's signature and record_id only. It is NOT
     * proof of source-chain finality. */
    sb_raw(b, ",\"reporter_signature_valid\":"); sb_bool(b, cn_activity_verify(a) == SC_OK);
    sb_raw(b, "}");
}

static bool parse_chain(const char *v, int *out)
{
    if (!strcmp(v, "a") || !strcmp(v, "A")) { *out = CN_CHAIN_A; return true; }
    if (!strcmp(v, "b") || !strcmp(v, "B")) { *out = CN_CHAIN_B; return true; }
    return false;
}

static void ep_activity_list(cn_http_t *h, const qp_t *q, size_t nq, resp_t *r)
{
    static const char *const allowed[] = {"chain", "type", "status", "since", "limit", NULL};
    if (!known_key(q, nq, allowed)) { err_body(r, 400, "Bad Request", "bad_query", "unknown query parameter"); return; }
    int chain = -1, type = -1, status = -1; uint64_t since = 0, limit = LIMIT_DEFAULT;
    const char *v;
    if ((v = qget(q, nq, "chain")) && !parse_chain(v, &chain)) { err_body(r, 400, "Bad Request", "bad_query", "chain must be a or b"); return; }
    if ((v = qget(q, nq, "type"))) {
        if (!strcmp(v, "same_chain")) type = CN_TX_TYPE_SAME_CHAIN;
        else if (!strcmp(v, "cross_chain")) type = CN_TX_TYPE_CROSS_CHAIN;
        else { err_body(r, 400, "Bad Request", "bad_query", "type must be same_chain or cross_chain"); return; }
    }
    if ((v = qget(q, nq, "status"))) {
        for (int s = 0; s <= CN_STATUS_UNAVAILABLE; s++) if (!strcmp(v, act_status((uint8_t)s))) status = s;
        if (status < 0) { err_body(r, 400, "Bad Request", "bad_query", "unknown status"); return; }
    }
    if ((v = qget(q, nq, "since")) && !parse_u64(v, &since)) { err_body(r, 400, "Bad Request", "bad_query", "since must be an unsigned integer"); return; }
    if ((v = qget(q, nq, "limit")) && (!parse_u64(v, &limit) || limit < 1 || limit > LIMIT_MAX)) {
        err_body(r, 400, "Bad Request", "bad_query", "limit must be 1..200"); return; }

    /* Oldest-first from `since` (exclusive). seq is 1-based in store order. */
    enum { CHUNK = 128 };
    cn_activity_record_t *buf = malloc(CHUNK * sizeof(*buf));
    if (!buf) { err_body(r, 500, "Internal Server Error", "internal", "out of memory"); return; }
    uint64_t total = cn_store_activity_count(h->ctx.store), cursor = since, found = 0, next_since = since;
    bool more = false; sb_t *b = &r->body;
    sb_raw(b, "{\"records\":[");
    while (cursor < total && !more) {
        size_t got = 0;
        if (cn_store_get_activity_since(h->ctx.store, cursor, buf, CHUNK, &got) != SC_OK || got == 0) break;
        for (size_t i = 0; i < got; i++) {
            uint64_t seq = cursor + 1 + i;
            const cn_activity_record_t *a = &buf[i];
            if ((chain >= 0 && a->source_chain != chain) || (type >= 0 && a->tx_type != type) || (status >= 0 && a->status != status)) {
                if (found < limit) next_since = seq;
                continue;
            }
            if (found >= limit) { more = true; break; }
            if (found) sb_raw(b, ",");
            write_activity(b, a, seq);
            found++; next_since = seq;
        }
        cursor += got;
    }
    free(buf);
    sb_raw(b, "],\"next_since\":"); sb_u64(b, next_since);
    sb_raw(b, ",\"has_more\":"); sb_bool(b, more);
    sb_raw(b, ",\"total_stored\":"); sb_u64(b, total); sb_raw(b, "}");
}

static void ep_activity_one(cn_http_t *h, const char *id_hex, resp_t *r)
{
    uint8_t id[32];
    if (strlen(id_hex) != 64 || !crypto_hex_decode(id_hex, id, 32)) { err_body(r, 400, "Bad Request", "bad_id", "record id must be 64 hex characters"); return; }
    cn_activity_record_t a;
    if (cn_store_get_activity_by_id(h->ctx.store, id, &a) != SC_OK) { err_body(r, 404, "Not Found", "not_found", "no such activity record"); return; }
    uint64_t total = cn_store_activity_count(h->ctx.store), seq = 0;
    cn_activity_record_t *buf = malloc(128 * sizeof(*buf));
    if (!buf) { err_body(r, 500, "Internal Server Error", "internal", "out of memory"); return; }
    for (uint64_t cur = 0; cur < total && !seq;) {
        size_t got = 0;
        if (cn_store_get_activity_since(h->ctx.store, cur, buf, 128, &got) != SC_OK || !got) break;
        for (size_t i = 0; i < got; i++) if (!memcmp(buf[i].record_id, id, 32)) { seq = cur + 1 + i; break; }
        cur += got;
    }
    free(buf);
    write_activity(&r->body, &a, seq);
}

static void write_transfer(sb_t *b, const cn_transfer_t *t, int quorum)
{
    sb_raw(b, "{\"transfer_id\":"); sb_hex(b, t->transfer_id, 32);
    sb_printf(b, ",\"source_chain\":\"%c\",\"dest_chain\":\"%c\",\"source_tx_hash\":", chain_ch(t->source_chain), chain_ch(t->dest_chain));
    sb_hex(b, t->source_tx_hash, 32);
    sb_raw(b, ",\"sender\":"); sb_hex(b, t->sender, 32);
    sb_raw(b, ",\"recipient\":"); sb_hex(b, t->recipient, 32);
    sb_raw(b, ",\"source_amount\":"); sb_u64(b, t->source_amount);
    sb_raw(b, ",\"dest_amount\":"); sb_u64(b, t->dest_amount);
    sb_raw(b, ",\"rate\":{\"num\":"); sb_u64(b, t->rate_num);
    sb_raw(b, ",\"den\":"); sb_u64(b, t->rate_den);
    sb_raw(b, ",\"version\":"); sb_u64(b, t->rate_version);
    sb_printf(b, "},\"state\":\"%s\",\"initiated_at\":%" PRId64 ",\"last_updated_at\":%" PRId64
                 ",\"approvals\":{\"count\":%zu,\"quorum\":%d,\"signers\":[",
              xfr_state(t->state), t->initiated_at, t->last_updated_at, t->cert_sig_count, quorum);
    size_t n = t->cert_sig_count < CN_MAX_PEERS ? t->cert_sig_count : CN_MAX_PEERS;
    for (size_t i = 0; i < n; i++) { if (i) sb_raw(b, ","); sb_hex(b, t->cert_signers[i], 32); }
    sb_raw(b, "]},\"dest_tx_hash\":");
    if (t->dest_tx_hash_valid) sb_hex(b, t->dest_tx_hash, 32); else sb_raw(b, "null");
    sb_raw(b, ",\"error_detail\":");
    if (t->error_detail[0]) { char e[257]; memcpy(e, t->error_detail, 256); e[256] = 0; sb_str(b, e); } else sb_raw(b, "null");
    sb_raw(b, "}");
}

static void ep_transfers_list(cn_http_t *h, const qp_t *q, size_t nq, resp_t *r)
{
    static const char *const allowed[] = {"state", "source_chain", "offset", "limit", NULL};
    if (!known_key(q, nq, allowed)) { err_body(r, 400, "Bad Request", "bad_query", "unknown query parameter"); return; }
    int state = -1, chain = -1; uint64_t offset = 0, limit = LIMIT_DEFAULT; const char *v;
    if ((v = qget(q, nq, "state"))) {
        for (int s = 0; s < 8; s++) if (!strcmp(v, xfr_state((uint8_t)s))) state = s;
        if (state < 0) { err_body(r, 400, "Bad Request", "bad_query", "unknown transfer state"); return; }
    }
    if ((v = qget(q, nq, "source_chain")) && !parse_chain(v, &chain)) { err_body(r, 400, "Bad Request", "bad_query", "source_chain must be a or b"); return; }
    if ((v = qget(q, nq, "offset")) && !parse_u64(v, &offset)) { err_body(r, 400, "Bad Request", "bad_query", "offset must be an unsigned integer"); return; }
    if ((v = qget(q, nq, "limit")) && (!parse_u64(v, &limit) || limit < 1 || limit > LIMIT_MAX)) { err_body(r, 400, "Bad Request", "bad_query", "limit must be 1..200"); return; }
    cn_transfer_t *t = malloc(sizeof(*t));
    if (!t) { err_body(r, 500, "Internal Server Error", "internal", "out of memory"); return; }
    size_t total = cn_store_transfer_count(h->ctx.store);
    uint64_t matched = 0, emitted = 0; sb_t *b = &r->body;
    sb_raw(b, "{\"transfers\":[");
    for (size_t k = 0; k < total; k++) { /* newest first */
        if (cn_store_get_transfer_at(h->ctx.store, total - 1 - k, t) != SC_OK) continue;
        if ((state >= 0 && t->state != state) || (chain >= 0 && t->source_chain != chain)) continue;
        if (matched++ < offset) continue;
        if (emitted >= limit) continue;
        if (emitted) sb_raw(b, ",");
        write_transfer(b, t, h->ctx.cfg->quorum);
        emitted++;
    }
    free(t);
    sb_raw(b, "],\"total_matching\":"); sb_u64(b, matched);
    sb_raw(b, ",\"offset\":"); sb_u64(b, offset);
    sb_raw(b, ",\"has_more\":"); sb_bool(b, matched > offset + emitted); sb_raw(b, "}");
}

static void ep_transfer_one(cn_http_t *h, const char *id_hex, resp_t *r)
{
    uint8_t id[32];
    if (strlen(id_hex) != 64 || !crypto_hex_decode(id_hex, id, 32)) { err_body(r, 400, "Bad Request", "bad_id", "transfer id must be 64 hex characters"); return; }
    cn_transfer_t *t = malloc(sizeof(*t));
    if (!t) { err_body(r, 500, "Internal Server Error", "internal", "out of memory"); return; }
    if (cn_store_get_transfer(h->ctx.store, id, t) != SC_OK) err_body(r, 404, "Not Found", "not_found", "no such transfer");
    else write_transfer(&r->body, t, h->ctx.cfg->quorum);
    free(t);
}

static void write_rate(sb_t *b, const cn_rate_t *x, const char *dir)
{
    sb_printf(b, "{\"direction\":\"%s\",\"num\":", dir); sb_u64(b, x->rate_num);
    sb_raw(b, ",\"den\":"); sb_u64(b, x->rate_den);
    sb_raw(b, ",\"version\":"); sb_u64(b, x->version);
    sb_raw(b, ",\"updated_at\":");
    if (x->updated_at > 0) sb_printf(b, "%" PRId64, x->updated_at); else sb_raw(b, "null");
    sb_raw(b, ",\"updater_pubkey\":");
    if (all_zero(x->updater_pubkey, 32)) sb_raw(b, "null"); else sb_hex(b, x->updater_pubkey, 32);
    /* true only if the stored signature verifies; config defaults are unsigned */
    sb_raw(b, ",\"signature_valid\":"); sb_bool(b, cn_rate_verify(x) == SC_OK);
    sb_raw(b, ",\"valid\":"); sb_bool(b, cn_rate_validate(x) == SC_OK); sb_raw(b, "}");
}

static void ep_rates(cn_http_t *h, resp_t *r)
{
    sb_t *b = &r->body;
    sb_raw(b, "{\"rates\":[");
    write_rate(b, h->ctx.rate_a_to_b, "A_to_B"); sb_raw(b, ",");
    write_rate(b, h->ctx.rate_b_to_a, "B_to_A");
    sb_raw(b, "],\"conversion\":\"dest_amount = floor(source_amount * num / den)\","
              "\"precision\":\"integer base units; no floating point\","
              "\"in_flight_transfers\":\"keep the rate frozen at detection time\"}");
}

/* ---------- request dispatch ---------- */
static bool header_get(const char *req, const char *name, char *out, size_t outlen)
{
    size_t nl = strlen(name);
    const char *p = strstr(req, "\r\n");
    while (p) {
        p += 2;
        if (!strncmp(p, "\r\n", 2)) break;
        if (!strncasecmp(p, name, nl) && p[nl] == ':') {
            p += nl + 1;
            while (*p == ' ' || *p == '\t') p++;
            const char *e = strstr(p, "\r\n");
            size_t l = e ? (size_t)(e - p) : strlen(p);
            while (l && (p[l - 1] == ' ' || p[l - 1] == '\t')) l--;
            if (l >= outlen) return false;
            memcpy(out, p, l); out[l] = 0;
            return true;
        }
        p = strstr(p, "\r\n");
    }
    return false;
}

static bool host_ok(const cn_http_t *h, const char *req)
{
    if (!h->loopback) return true;
    char host[128];
    if (!header_get(req, "Host", host, sizeof(host))) return false;
    return !strncmp(host, "127.0.0.1", 9) || !strncmp(host, "localhost", 9) || !strncmp(host, "[::1]", 5);
}

static void route(cn_http_t *h, const char *method, char *target, const char *req, resp_t *r, bool *cors_ok)
{
    char origin[160];
    *cors_ok = h->has_origin && header_get(req, "Origin", origin, sizeof(origin)) && !strcmp(origin, h->origin);
    if (!host_ok(h, req)) { err_body(r, 403, "Forbidden", "bad_host", "Host header not allowed"); return; }
    if (!strcmp(method, "OPTIONS")) {
        if (!*cors_ok) { err_body(r, 403, "Forbidden", "cors_denied", "origin not allowed"); return; }
        r->status = 204; r->reason = "No Content"; return;
    }
    if (strcmp(method, "GET") != 0) { err_body(r, 405, "Method Not Allowed", "method_not_allowed", "this API is read-only: GET only"); return; }
    char *qs = strchr(target, '?');
    if (qs) *qs++ = 0;
    qp_t q[MAX_QP]; size_t nq = 0;
    if (!parse_query(qs, q, &nq)) { err_body(r, 400, "Bad Request", "bad_query", "malformed query string"); return; }
    r->status = 200; r->reason = "OK";
    if (!strcmp(target, "/api/status")) ep_status(h, r);
    else if (!strcmp(target, "/api/topology")) ep_topology(h, r);
    else if (!strcmp(target, "/api/activity")) ep_activity_list(h, q, nq, r);
    else if (!strncmp(target, "/api/activity/", 14)) ep_activity_one(h, target + 14, r);
    else if (!strcmp(target, "/api/transfers")) ep_transfers_list(h, q, nq, r);
    else if (!strncmp(target, "/api/transfers/", 15)) ep_transfer_one(h, target + 15, r);
    else if (!strcmp(target, "/api/rates")) ep_rates(h, r);
    else err_body(r, 404, "Not Found", "not_found", "unknown endpoint");
}

static void build_response(cn_http_t *h, client_t *c)
{
    resp_t r; memset(&r, 0, sizeof(r));
    bool cors_ok = false;
    char method[8], target[512], ver[16];
    char *line_end = strstr(c->in, "\r\n");
    if (!line_end) { c->in[0] = 0; }
    else *line_end = 0;
    if (!line_end || sscanf(c->in, "%7s %511s %15s", method, target, ver) != 3 || strncmp(ver, "HTTP/1.", 7) != 0) {
        err_body(&r, 400, "Bad Request", "bad_request", "malformed request line");
    } else {
        *line_end = '\r';
        route(h, method, target, c->in, &r, &cors_ok);
    }
    char head[768];
    int hl = snprintf(head, sizeof(head),
        "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nCache-Control: no-store\r\n"
        "X-Content-Type-Options: nosniff\r\nConnection: close\r\nContent-Length: %zu\r\n%s%s",
        r.status, r.reason, r.status == 204 ? 0 : r.body.len,
        cors_ok ? "Access-Control-Allow-Methods: GET, OPTIONS\r\nAccess-Control-Allow-Headers: Accept, Content-Type\r\nAccess-Control-Max-Age: 600\r\nVary: Origin\r\nAccess-Control-Allow-Origin: " : "",
        cors_ok ? h->origin : "");
    if (hl < 0 || (size_t)hl >= sizeof(head)) { free(r.body.p); return; }
    sb_t out = {0};
    sb_put(&out, head, (size_t)hl);
    if (cors_ok) sb_raw(&out, "\r\n");
    sb_raw(&out, "\r\n");
    if (r.status != 204 && r.body.p) sb_put(&out, r.body.p, r.body.len);
    free(r.body.p);
    if (out.oom) { free(out.p); return; }
    c->out = out.p; c->out_len = out.len; c->out_off = 0;
    c->responding = true;
    c->deadline_ms = mono_ms() + HTTP_IDLE_MS;
}

/* ---------- socket loop ---------- */
static void client_close(client_t *c)
{
    if (c->fd >= 0) close(c->fd);
    free(c->out);
    memset(c, 0, sizeof(*c));
    c->fd = -1;
}

sc_err_t cn_http_init(cn_http_t **out, const char *host, uint16_t port,
                      const char *allowed_origin, const cn_http_ctx_t *ctx,
                      char *errbuf, size_t errlen)
{
    struct sockaddr_in sa; memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET; sa.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &sa.sin_addr) != 1) { snprintf(errbuf, errlen, "invalid http host '%s' (IPv4 required)", host); return SC_ERR_INVALID; }
    if (allowed_origin && (strlen(allowed_origin) >= sizeof(((cn_http_t *)0)->origin) || strchr(allowed_origin, '\r') || strchr(allowed_origin, '\n') || strcmp(allowed_origin, "*") == 0)) {
        snprintf(errbuf, errlen, "invalid --http-origin (wildcards are not allowed)"); return SC_ERR_INVALID; }
    cn_http_t *h = calloc(1, sizeof(*h));
    if (!h) { snprintf(errbuf, errlen, "out of memory"); return SC_ERR_IO; }
    h->ctx = *ctx; h->started_s = (int64_t)time(NULL);
    h->loopback = (ntohl(sa.sin_addr.s_addr) >> 24) == 127;
    if (allowed_origin) { snprintf(h->origin, sizeof(h->origin), "%s", allowed_origin); h->has_origin = true; }
    for (int i = 0; i < HTTP_MAX_CLIENTS; i++) h->clients[i].fd = -1;
    h->lfd = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    if (h->lfd < 0 || setsockopt(h->lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != 0 ||
        bind(h->lfd, (struct sockaddr *)&sa, sizeof(sa)) != 0 || listen(h->lfd, 16) != 0 ||
        fcntl(h->lfd, F_SETFL, O_NONBLOCK) != 0) {
        snprintf(errbuf, errlen, "cannot listen on %s:%u: %s", host, (unsigned)port, strerror(errno));
        if (h->lfd >= 0) close(h->lfd);
        free(h);
        return SC_ERR_IO;
    }
    if (!h->loopback) log_event(LOG_WARN, "http", "non_loopback_bind_api_has_no_authentication");
    *out = h;
    return SC_OK;
}

void cn_http_poll_step(cn_http_t *h, int timeout_ms)
{
    if (!h) return;
    struct pollfd pf[HTTP_MAX_CLIENTS + 1]; int idx[HTTP_MAX_CLIENTS + 1]; nfds_t n = 0;
    pf[n].fd = h->lfd; pf[n].events = POLLIN; idx[n++] = -1;
    int64_t now = mono_ms();
    for (int i = 0; i < HTTP_MAX_CLIENTS; i++) {
        client_t *c = &h->clients[i];
        if (c->fd < 0) continue;
        if (now > c->deadline_ms) { client_close(c); continue; }
        pf[n].fd = c->fd; pf[n].events = c->responding ? POLLOUT : POLLIN; idx[n++] = i;
    }
    if (poll(pf, n, timeout_ms) <= 0) return;
    for (nfds_t k = 0; k < n; k++) {
        if (!pf[k].revents) continue;
        if (idx[k] < 0) {
            for (;;) {
                int fd = accept(h->lfd, NULL, NULL);
                if (fd < 0) break;
                int slot = -1;
                for (int i = 0; i < HTTP_MAX_CLIENTS; i++) if (h->clients[i].fd < 0) { slot = i; break; }
                if (slot < 0 || fcntl(fd, F_SETFL, O_NONBLOCK) != 0) { close(fd); continue; }
                client_t *c = &h->clients[slot];
                memset(c, 0, sizeof(*c)); c->fd = fd; c->deadline_ms = mono_ms() + HTTP_IDLE_MS;
            }
            continue;
        }
        client_t *c = &h->clients[idx[k]];
        if (!c->responding && (pf[k].revents & (POLLIN | POLLHUP | POLLERR))) {
            ssize_t got = recv(c->fd, c->in + c->in_len, HTTP_MAX_REQ - c->in_len, 0);
            if (got <= 0) { if (got < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) continue; client_close(c); continue; }
            c->in_len += (size_t)got; c->in[c->in_len] = 0;
            if (strstr(c->in, "\r\n\r\n")) build_response(h, c);
            else if (c->in_len >= HTTP_MAX_REQ) {
                static const char tooBig[] = "HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
                (void)send(c->fd, tooBig, sizeof(tooBig) - 1, MSG_NOSIGNAL);
                client_close(c); continue;
            }
            if (!c->responding && !c->out) continue;
            if (!c->out) { client_close(c); continue; }
        }
        if (c->responding && c->out) {
            ssize_t sent = send(c->fd, c->out + c->out_off, c->out_len - c->out_off, MSG_NOSIGNAL);
            if (sent < 0 && errno != EAGAIN && errno != EWOULDBLOCK) { client_close(c); continue; }
            if (sent > 0) c->out_off += (size_t)sent;
            if (c->out_off >= c->out_len) client_close(c);
        }
    }
}

void cn_http_shutdown(cn_http_t *h)
{
    if (!h) return;
    for (int i = 0; i < HTTP_MAX_CLIENTS; i++) if (h->clients[i].fd >= 0) client_close(&h->clients[i]);
    if (h->lfd >= 0) close(h->lfd);
    free(h);
}
