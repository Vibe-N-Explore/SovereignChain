/* cn_http.h - Minimal read-only HTTP/1.1 JSON API for the connector daemon.
 *
 * Runs inside the daemon's existing poll loop (single thread, non-blocking).
 * Disabled unless the operator passes --http-port. Only GET and OPTIONS are
 * served; no endpoint changes state. Amounts and other u64 values are emitted
 * as decimal STRINGS so browsers never lose precision.
 */
#ifndef CN_HTTP_H
#define CN_HTTP_H

#include "cn_chain.h"
#include "cn_net.h"
#include "cn_store.h"
#include "connector_types.h"

typedef struct cn_http cn_http_t;

/* Pointers must stay valid for the lifetime of the server. chain_a, chain_b
 * and net may be NULL (reported as not connected). Rates are read live. */
typedef struct {
    const cn_config_t *cfg;
    const uint8_t     *my_pubkey;     /* 32 bytes, public */
    cn_store_t        *store;
    cn_net_t          *net;
    cn_chain_conn_t   *chain_a;
    cn_chain_conn_t   *chain_b;
    const cn_rate_t   *rate_a_to_b;
    const cn_rate_t   *rate_b_to_a;
} cn_http_ctx_t;

/* allowed_origin: exact Origin value to allow via CORS (e.g. "http://127.0.0.1:8081",
 * or "null" for pages opened from file://). NULL disables CORS headers. */
sc_err_t cn_http_init(cn_http_t **out, const char *host, uint16_t port,
                      const char *allowed_origin, const cn_http_ctx_t *ctx,
                      char *errbuf, size_t errlen);
void cn_http_poll_step(cn_http_t *h, int timeout_ms);
void cn_http_shutdown(cn_http_t *h);

#endif /* CN_HTTP_H */
