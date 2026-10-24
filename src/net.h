/* net.h - SovereignChain networking subsystem (Phase 2: framed TCP).
 *
 * Provides non-blocking, length-prefixed TCP communication between all nodes
 * in the network using poll() and non-blocking sockets.
 *
 * Frame Format on the Wire (Network Byte Order / Big Endian):
 *   +-----------------------------+-------------------+-------------------+
 *   | payload_len (4 bytes, u32)  | type (2 bytes, u16)| reserved (2 bytes)|
 *   +-----------------------------+-------------------+-------------------+
 *   |                      payload bytes (payload_len)                    |
 *   +---------------------------------------------------------------------+
 *
 * Header size = 8 bytes.
 * Maximum payload size = 64 KB (SC_NET_MAX_PAYLOAD).
 */
#ifndef SC_NET_H
#define SC_NET_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "config.h"
#include "err.h"

#define SC_NET_MAX_PAYLOAD (64 * 1024) /* 64 KB max payload per frame */
#define SC_NET_HEADER_LEN  8

typedef enum {
    MSG_TYPE_HELLO = 1, /* Peer identification on connect: sender_id (u32) */
    MSG_TYPE_PING  = 2, /* Heartbeat */
    MSG_TYPE_PONG  = 3, /* Response to heartbeat */
    MSG_TYPE_TEST  = 4  /* Test payload */
} sc_msg_type_t;

/* Header parsed into host byte order */
typedef struct {
    uint32_t payload_len;
    uint16_t type;
    uint16_t reserved;
} sc_net_header_t;

/* Callback when a full message is received from a peer */
typedef void (*sc_net_msg_cb)(int from_node_id, uint16_t type,
                              const uint8_t *payload, size_t len, void *user);

/* Net subsystem state */
typedef struct sc_net sc_net_t;

/* Create and initialize networking subsystem for node 'me' */
sc_err_t net_init(sc_net_t **net_out, const network_config_t *topology,
                  const node_info_t *me, int listen_fd,
                  sc_net_msg_cb msg_cb, void *user,
                  char *errbuf, size_t errlen);

/* Free resources and close sockets */
void net_shutdown(sc_net_t *net);

/* Single iteration of poll() and network event processing.
 * timeout_ms: max time to block in poll(). */
sc_err_t net_poll_step(sc_net_t *net, int timeout_ms);

/* Enqueue a framed message to be sent to target_node_id.
 * If target is SC_BROADCAST_ALL (-1), sends to all connected peers. */
#define SC_BROADCAST_ALL -1
sc_err_t net_send(sc_net_t *net, int target_node_id, uint16_t type,
                  const void *payload, size_t len);

/* Returns true if connected to target peer */
bool net_is_connected(const sc_net_t *net, int target_node_id);

/* Count of currently connected peers */
size_t net_connected_count(const sc_net_t *net);

#endif /* SC_NET_H */
