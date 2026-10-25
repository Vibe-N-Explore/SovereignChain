/* cn_chain.h - Blockchain node connection client. */
#ifndef CN_CHAIN_H
#define CN_CHAIN_H

#include "connector_types.h"

typedef void (*cn_chain_tx_cb)(uint8_t chain_id, const sc_tx_t *tx, void *user);
typedef void (*cn_chain_cert_cb)(uint8_t chain_id, const uint8_t *cert_payload, size_t len, void *user);

typedef struct cn_chain_conn cn_chain_conn_t;

/* Initialize and connect to chain node */
sc_err_t cn_chain_connect(cn_chain_conn_t **conn_out, const cn_chain_cfg_t *cfg,
                           const sc_keypair_t *my_kp,
                           cn_chain_tx_cb tx_cb, cn_chain_cert_cb cert_cb, void *user,
                           char *errbuf, size_t errlen);

/* Close connection and free resources */
void cn_chain_close(cn_chain_conn_t *conn);

/* Poll socket, process frames, reconnect if disconnected */
sc_err_t cn_chain_poll_step(cn_chain_conn_t *conn, int timeout_ms);

/* Submit transaction to the connected chain */
sc_err_t cn_chain_submit_tx(cn_chain_conn_t *conn, const sc_tx_t *tx);

/* True if connected and authenticated with chain node */
bool cn_chain_is_connected(const cn_chain_conn_t *conn);

#endif /* CN_CHAIN_H */
