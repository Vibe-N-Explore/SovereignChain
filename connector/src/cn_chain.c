/* cn_chain.c - Blockchain node connection and interaction client. */
#define _POSIX_C_SOURCE 200809L

#include "cn_chain.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "../../src/crypto.h"
#include "../../src/err.h"
#include "../../src/log.h"
#include "../../src/net.h"
#include "../../src/tx.h"

#define RECONNECT_INTERVAL_MS 1500
#define BUF_SIZE              (CN_NET_HEADER_LEN + CN_NET_MAX_PAYLOAD)

typedef enum {
    CHAIN_DISCONNECTED = 0,
    CHAIN_CONNECTING,
    CHAIN_HS_INIT_SENT,
    CHAIN_CONNECTED
} chain_state_t;

struct cn_chain_conn {
    cn_chain_cfg_t        cfg;
    const sc_keypair_t   *my_keypair;
    cn_chain_tx_cb        tx_cb;
    cn_chain_cert_cb      cert_cb;
    void                 *user_data;

    chain_state_t         state;
    int                   fd;
    int64_t               next_reconnect_ms;

    uint8_t               in_buf[BUF_SIZE];
    size_t                in_len;

    uint8_t               out_buf[BUF_SIZE];
    size_t                out_len;
};

static int64_t get_now_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return ((int64_t)ts.tv_sec * 1000) + (ts.tv_nsec / 1000000L);
}

static sc_err_t set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0)
        return SC_ERR_IO;
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
        return SC_ERR_IO;
    return SC_OK;
}

static void close_conn(cn_chain_conn_t *conn, const char *reason)
{
    if (conn->fd >= 0) {
        log_eventf(LOG_INFO, "cn_chain", "chain_disconnected",
                   "chain=%u reason=\"%s\"", (unsigned)conn->cfg.chain_id, reason ? reason : "closed");
        close(conn->fd);
        conn->fd = -1;
    }
    conn->state = CHAIN_DISCONNECTED;
    conn->in_len = 0;
    conn->out_len = 0;
    conn->next_reconnect_ms = get_now_ms() + RECONNECT_INTERVAL_MS;
}

static bool enqueue_frame(cn_chain_conn_t *conn, uint16_t type, const void *payload, size_t len)
{
    if (len > CN_NET_MAX_PAYLOAD)
        return false;
    size_t total = CN_NET_HEADER_LEN + len;
    if (sizeof(conn->out_buf) - conn->out_len < total)
        return false;

    uint32_t net_len  = htonl((uint32_t)len);
    uint16_t net_type = htons(type);
    uint16_t net_res  = 0;

    uint8_t *dest = conn->out_buf + conn->out_len;
    memcpy(dest,     &net_len,  4);
    memcpy(dest + 4, &net_type, 2);
    memcpy(dest + 6, &net_res,  2);
    if (len > 0 && payload)
        memcpy(dest + CN_NET_HEADER_LEN, payload, len);

    conn->out_len += total;
    return true;
}

static bool flush_out(cn_chain_conn_t *conn)
{
    if (conn->out_len == 0)
        return true;
    ssize_t sent = send(conn->fd, conn->out_buf, conn->out_len, 0);
    if (sent > 0) {
        size_t rem = conn->out_len - (size_t)sent;
        if (rem > 0)
            memmove(conn->out_buf, conn->out_buf + sent, rem);
        conn->out_len = rem;
        return true;
    }
    if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
        return true;
    return false;
}

static void send_hello_init(cn_chain_conn_t *conn)
{
    uint8_t buf[SC_HELLO_INIT_LEN];
    uint8_t my_pubkey[SC_ED25519_PUBKEY_LEN];

    if (crypto_get_pubkey(conn->my_keypair, my_pubkey) != SC_OK) {
        close_conn(conn, "cannot get own pubkey");
        return;
    }

    uint32_t my_id_net = htonl((uint32_t)conn->cfg.our_node_id);
    memcpy(buf,     &my_id_net, 4);
    memcpy(buf + 4, my_pubkey, SC_ED25519_PUBKEY_LEN);

    if (!enqueue_frame(conn, MSG_TYPE_HELLO_INIT, buf, sizeof(buf))) {
        close_conn(conn, "hello_init enqueue failed");
        return;
    }
    conn->state = CHAIN_HS_INIT_SENT;
}

static void handle_hello_chal(cn_chain_conn_t *conn, const uint8_t *payload, size_t len)
{
    if (len != SC_HELLO_CHAL_LEN) {
        close_conn(conn, "bad HELLO_CHAL length");
        return;
    }
    const uint8_t *nonce       = payload;
    const uint8_t *node_pubkey = payload + SC_NONCE_LEN;
    const uint8_t *node_sig    = payload + SC_NONCE_LEN + SC_ED25519_PUBKEY_LEN;

    if (conn->cfg.has_pubkey && memcmp(node_pubkey, conn->cfg.pubkey, SC_ED25519_PUBKEY_LEN) != 0) {
        close_conn(conn, "chain node pubkey mismatch");
        return;
    }

    sc_keypair_t *node_kp = NULL;
    if (crypto_pubkey_from_raw(&node_kp, node_pubkey) != SC_OK) {
        close_conn(conn, "cannot parse chain node pubkey");
        return;
    }

    sc_err_t vrc = crypto_verify(node_kp, nonce, SC_NONCE_LEN, node_sig);
    crypto_keypair_free(node_kp);

    if (vrc != SC_OK) {
        close_conn(conn, "chain node signature invalid");
        return;
    }

    /* Sign nonce and reply with HELLO_RESP */
    uint8_t my_sig[SC_ED25519_SIG_LEN];
    if (crypto_sign(conn->my_keypair, nonce, SC_NONCE_LEN, my_sig) != SC_OK) {
        close_conn(conn, "HELLO_RESP sign failed");
        return;
    }
    if (!enqueue_frame(conn, MSG_TYPE_HELLO_RESP, my_sig, sizeof(my_sig))) {
        close_conn(conn, "HELLO_RESP enqueue failed");
        return;
    }

    conn->state = CHAIN_CONNECTED;
    log_eventf(LOG_INFO, "cn_chain", "connected_to_chain",
               "chain=%u node_id=%d", (unsigned)conn->cfg.chain_id, conn->cfg.our_node_id);
}

static void start_connect(cn_chain_conn_t *conn)
{
    conn->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (conn->fd < 0) {
        conn->next_reconnect_ms = get_now_ms() + RECONNECT_INTERVAL_MS;
        return;
    }
    set_nonblocking(conn->fd);

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(conn->cfg.port);
    inet_pton(AF_INET, conn->cfg.host, &sa.sin_addr);

    int rc = connect(conn->fd, (struct sockaddr *)&sa, sizeof(sa));
    if (rc == 0 || errno == EINPROGRESS) {
        conn->state = CHAIN_CONNECTING;
    } else {
        close_conn(conn, "connect failed");
    }
}

sc_err_t cn_chain_connect(cn_chain_conn_t **conn_out, const cn_chain_cfg_t *cfg,
                           const sc_keypair_t *my_kp,
                           cn_chain_tx_cb tx_cb, cn_chain_cert_cb cert_cb, void *user,
                           char *errbuf, size_t errlen)
{
    if (!conn_out || !cfg || !my_kp) {
        if (errbuf && errlen)
            snprintf(errbuf, errlen, "null argument");
        return SC_ERR_INVALID;
    }

    cn_chain_conn_t *conn = calloc(1, sizeof(*conn));
    if (!conn)
        return SC_ERR_IO;

    conn->cfg        = *cfg;
    conn->my_keypair = my_kp;
    conn->tx_cb      = tx_cb;
    conn->cert_cb    = cert_cb;
    conn->user_data  = user;
    conn->fd         = -1;
    conn->state      = CHAIN_DISCONNECTED;

    start_connect(conn);

    *conn_out = conn;
    return SC_OK;
}

void cn_chain_close(cn_chain_conn_t *conn)
{
    if (!conn)
        return;

    if (conn->fd >= 0) {
        close(conn->fd);
        conn->fd = -1;
    }
    free(conn);
}

sc_err_t cn_chain_poll_step(cn_chain_conn_t *conn, int timeout_ms)
{
    if (!conn)
        return SC_ERR_INVALID;

    int64_t now = get_now_ms();
    if (conn->state == CHAIN_DISCONNECTED && now >= conn->next_reconnect_ms) {
        start_connect(conn);
    }

    if (conn->fd < 0)
        return SC_OK;

    struct pollfd pfd;
    pfd.fd = conn->fd;
    pfd.events = POLLIN;
    if (conn->state == CHAIN_CONNECTING || conn->out_len > 0)
        pfd.events |= POLLOUT;
    pfd.revents = 0;

    int rc = poll(&pfd, 1, timeout_ms);
    if (rc <= 0)
        return SC_OK;

    if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
        close_conn(conn, "poll error");
        return SC_OK;
    }

    if (conn->state == CHAIN_CONNECTING && (pfd.revents & POLLOUT)) {
        int err = 0;
        socklen_t len = sizeof(err);
        getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, &err, &len);
        if (err == 0) {
            send_hello_init(conn);
        } else {
            close_conn(conn, "connection refused");
            return SC_OK;
        }
    }

    if (pfd.revents & POLLOUT) {
        if (!flush_out(conn)) {
            close_conn(conn, "flush error");
            return SC_OK;
        }
    }

    if (pfd.revents & POLLIN) {
        ssize_t n = recv(conn->fd, conn->in_buf + conn->in_len,
                         sizeof(conn->in_buf) - conn->in_len, 0);
        if (n <= 0) {
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
                /* ok */
            } else {
                close_conn(conn, n == 0 ? "chain node closed connection" : "recv error");
                return SC_OK;
            }
        } else {
            conn->in_len += (size_t)n;
            while (conn->in_len >= CN_NET_HEADER_LEN) {
                uint32_t net_len;
                uint16_t net_type;
                memcpy(&net_len,  conn->in_buf,     4);
                memcpy(&net_type, conn->in_buf + 4, 2);
                uint32_t payload_len = ntohl(net_len);
                uint16_t msg_type    = ntohs(net_type);

                if (payload_len > CN_NET_MAX_PAYLOAD) {
                    close_conn(conn, "frame too large");
                    break;
                }

                size_t frame_total = CN_NET_HEADER_LEN + payload_len;
                if (conn->in_len < frame_total)
                    break;

                const uint8_t *payload = conn->in_buf + CN_NET_HEADER_LEN;

                if (conn->state == CHAIN_HS_INIT_SENT && msg_type == MSG_TYPE_HELLO_CHAL) {
                    handle_hello_chal(conn, payload, payload_len);
                } else if (conn->state == CHAIN_CONNECTED) {
                    if (msg_type == MSG_TYPE_PING) {
                        enqueue_frame(conn, MSG_TYPE_PONG, NULL, 0);
                    } else if (msg_type == MSG_TYPE_TX) {
                        sc_tx_t tx;
                        if (tx_deserialize(&tx, payload, payload_len) == SC_OK) {
                            if (tx_verify_sig(&tx) == SC_OK) {
                                if (conn->tx_cb) {
                                    conn->tx_cb(conn->cfg.chain_id, &tx, conn->user_data);
                                }
                            }
                        }
                    } else if (msg_type == MSG_TYPE_CERT) {
                        if (conn->cert_cb) {
                            conn->cert_cb(conn->cfg.chain_id, payload, payload_len, conn->user_data);
                        }
                    }
                }

                size_t rem = conn->in_len - frame_total;
                if (rem > 0)
                    memmove(conn->in_buf, conn->in_buf + frame_total, rem);
                conn->in_len = rem;
            }
        }
    }

    return SC_OK;
}

sc_err_t cn_chain_submit_tx(cn_chain_conn_t *conn, const sc_tx_t *tx)
{
    if (!conn || !tx)
        return SC_ERR_INVALID;

    if (conn->state != CHAIN_CONNECTED)
        return SC_ERR_IO;

    uint8_t wire[SC_TX_WIRE_LEN];
    size_t written = 0;
    if (tx_serialize(tx, wire, sizeof(wire), &written) != SC_OK)
        return SC_ERR_INVALID;

    if (!enqueue_frame(conn, MSG_TYPE_TX, wire, written))
        return SC_ERR_IO;

    return SC_OK;
}

bool cn_chain_is_connected(const cn_chain_conn_t *conn)
{
    return conn && (conn->state == CHAIN_CONNECTED);
}
