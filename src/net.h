/* net.h - SovereignChain networking subsystem (Phase 3: authenticated framed TCP).
 *
 * Phase 3 extends Phase 2 by replacing the plaintext MSG_TYPE_HELLO
 * with a 3-message Ed25519 challenge-response handshake:
 *
 *   1. Connector → Listener: HELLO_INIT   { sender_id(u32), pubkey(32 bytes) }
 *   2. Listener  → Connector: HELLO_CHAL  { nonce(32 bytes), pubkey(32 bytes),
 *                                           sig_of_nonce(64 bytes) }
 *   3. Connector → Listener: HELLO_RESP   { sig_of_nonce(64 bytes) }
 *
 * After step 3 both sides have verified that each peer:
 *   a) Presented the public key pinned in network.conf for their node_id
 *   b) Proved they own the corresponding private key by signing the nonce
 *
 * SECURITY NOTE: This provides PEER AUTHENTICATION only.
 * Wire traffic is NOT encrypted. An observer can read all payloads.
 * TLS (confidentiality) is deferred to a later phase.
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
#include "crypto.h"
#include "err.h"

#define SC_NET_MAX_PAYLOAD (64 * 1024) /* 64 KB max payload per frame */
#define SC_NET_HEADER_LEN  8

/* ---- Handshake payload sizes (fixed-length, no dynamic allocation) ---- */
#define SC_HELLO_INIT_LEN  (4 + SC_ED25519_PUBKEY_LEN)        /* 36 bytes */
#define SC_HELLO_CHAL_LEN  (SC_NONCE_LEN + SC_ED25519_PUBKEY_LEN + SC_ED25519_SIG_LEN)  /* 128 bytes */
#define SC_HELLO_RESP_LEN  (SC_ED25519_SIG_LEN)               /* 64 bytes */

typedef enum {
    /* Phase 3 authenticated handshake — replaces plaintext HELLO */
    MSG_TYPE_HELLO_INIT = 1, /* Connector→Listener: id + pubkey                  */
    MSG_TYPE_HELLO_CHAL = 2, /* Listener→Connector: nonce + pubkey + sig(nonce)   */
    MSG_TYPE_HELLO_RESP = 3, /* Connector→Listener: sig(nonce)                    */

    MSG_TYPE_PING       = 4, /* Heartbeat                                          */
    MSG_TYPE_PONG       = 5, /* Response to heartbeat                              */
    MSG_TYPE_TEST       = 6, /* Test payload (Phase 2 compatibility)               */
    MSG_TYPE_TX         = 7, /* Phase 4: Transaction gossip                        */
    MSG_TYPE_VERTEX     = 8, /* Phase 5: DAG vertex proposal                       */
    MSG_TYPE_VOTE       = 9, /* Phase 6: Vote on DAG vertex                        */
    MSG_TYPE_CERT       = 10 /* Phase 6: Certified vertex (2-of-2 quorum)           */
} sc_msg_type_t;

/* Header parsed into host byte order */
typedef struct {
    uint32_t payload_len;
    uint16_t type;
    uint16_t reserved;
} sc_net_header_t;

/* Callback when a full authenticated message is received from a peer.
 * 'from_node_id' is the cryptographically verified peer id.
 * Only called for non-handshake message types. */
typedef void (*sc_net_msg_cb)(int from_node_id, uint16_t type,
                              const uint8_t *payload, size_t len, void *user);

/* Net subsystem state (opaque to callers) */
typedef struct sc_net sc_net_t;

/* Create and initialize networking subsystem for node 'me'.
 * 'my_keypair' is this node's Ed25519 keypair (used to sign HELLO_CHAL/RESP).
 * It must outlive the sc_net_t. The net subsystem does NOT take ownership. */
sc_err_t net_init(sc_net_t **net_out, const network_config_t *topology,
                  const node_info_t *me, int listen_fd,
                  const sc_keypair_t *my_keypair,
                  sc_net_msg_cb msg_cb, void *user,
                  char *errbuf, size_t errlen);

/* Free resources and close sockets */
void net_shutdown(sc_net_t *net);

/* Single iteration of poll() and network event processing.
 * timeout_ms: max time to block in poll(). */
sc_err_t net_poll_step(sc_net_t *net, int timeout_ms);

/* Enqueue a framed message to be sent to target_node_id.
 * If target is SC_BROADCAST_ALL (-1), sends to all authenticated peers.
 * Rejects sends to peers that have not completed handshake. */
#define SC_BROADCAST_ALL -1
sc_err_t net_send(sc_net_t *net, int target_node_id, uint16_t type,
                  const void *payload, size_t len);

/* Returns true if connected AND handshake completed with target peer */
bool net_is_connected(const sc_net_t *net, int target_node_id);

/* Count of currently authenticated peers */
size_t net_connected_count(const sc_net_t *net);

#endif /* SC_NET_H */
