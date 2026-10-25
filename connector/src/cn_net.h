/* cn_net.h - Connector-to-connector authenticated networking. */
#ifndef CN_NET_H
#define CN_NET_H

#include "connector_types.h"

typedef void (*cn_net_msg_cb)(int from_peer_id, uint16_t type,
                               const uint8_t *payload, size_t len, void *user);

typedef struct cn_net cn_net_t;

sc_err_t cn_net_init(cn_net_t **net_out, const cn_config_t *cfg,
                     const sc_keypair_t *my_kp,
                     cn_net_msg_cb msg_cb, void *user,
                     char *errbuf, size_t errlen);
void cn_net_shutdown(cn_net_t *net);
sc_err_t cn_net_poll_step(cn_net_t *net, int timeout_ms);
sc_err_t cn_net_send(cn_net_t *net, int peer_id, uint16_t type,
                     const void *payload, size_t len);
sc_err_t cn_net_broadcast(cn_net_t *net, uint16_t type,
                           const void *payload, size_t len);
bool cn_net_is_connected(const cn_net_t *net, int peer_id);
size_t cn_net_connected_count(const cn_net_t *net);

#endif /* CN_NET_H */
