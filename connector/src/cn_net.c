/* cn_net.c - Connector-to-connector authenticated framed networking implementation. */
#define _POSIX_C_SOURCE 200809L

#include "cn_net.h"

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

#define RECONNECT_INTERVAL_MS 1000
#define MAX_PENDING_INBOUND   8
#define BUF_SIZE              (CN_NET_HEADER_LEN + CN_NET_MAX_PAYLOAD)

#define SC_HELLO_INIT_LEN  (4 + SC_ED25519_PUBKEY_LEN)                                   /* 36 bytes */
#define SC_HELLO_CHAL_LEN  (SC_NONCE_LEN + SC_ED25519_PUBKEY_LEN + SC_ED25519_SIG_LEN)  /* 128 bytes */
#define SC_HELLO_RESP_LEN  (SC_ED25519_SIG_LEN)                                          /* 64 bytes */

typedef enum {
    PEER_DISCONNECTED = 0,
    PEER_CONNECTING,       /* TCP SYN sent, waiting for POLLOUT */
    PEER_HS_INIT_SENT,     /* HELLO_INIT sent, waiting for HELLO_CHAL */
    PEER_HS_RESP_SENT,     /* HELLO_RESP sent */
    PEER_CONNECTED         /* Handshake complete */
} peer_state_t;

typedef struct {
    int          peer_id;
    char         host[CN_MAX_HOST];
    uint16_t     port;
    uint8_t      pubkey[SC_ED25519_PUBKEY_LEN];
    bool         has_pubkey;
    bool         is_target;       /* true = we initiate outbound connection */
    peer_state_t state;
    int          fd;
    int64_t      next_reconnect_ms;

    uint8_t      handshake_nonce[SC_NONCE_LEN];

    uint8_t      in_buf[BUF_SIZE];
    size_t       in_len;

    uint8_t      out_buf[BUF_SIZE];
    size_t       out_len;
} cn_peer_conn_t;

typedef enum {
    PEND_WAIT_INIT = 0,
    PEND_WAIT_RESP
} pend_state_t;

typedef struct {
    int          fd;
    pend_state_t hs_state;
    int          claimed_id;
    uint8_t      nonce[SC_NONCE_LEN];
    uint8_t      in_buf[BUF_SIZE];
    size_t       in_len;
    uint8_t      out_buf[BUF_SIZE];
    size_t       out_len;
} cn_pending_conn_t;

struct cn_net {
    int                   my_connector_id;
    const sc_keypair_t   *my_keypair;
    int                   listen_fd;
    cn_net_msg_cb         msg_cb;
    void                 *user_data;

    cn_peer_conn_t        peers[CN_MAX_PEERS];
    size_t                peer_count;

    cn_pending_conn_t     pending[MAX_PENDING_INBOUND];
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

static cn_peer_conn_t *find_peer(cn_net_t *net, int peer_id)
{
    for (size_t i = 0; i < net->peer_count; i++) {
        if (net->peers[i].peer_id == peer_id)
            return &net->peers[i];
    }
    return NULL;
}

static void close_peer(cn_peer_conn_t *p, const char *reason)
{
    if (p->fd >= 0) {
        log_eventf(LOG_INFO, "cn_net", "peer_disconnected",
                   "peer=%d reason=\"%s\"", p->peer_id, reason ? reason : "closed");
        close(p->fd);
        p->fd = -1;
    }
    p->state  = PEER_DISCONNECTED;
    p->in_len = 0;
    p->out_len = 0;
    p->next_reconnect_ms = get_now_ms() + RECONNECT_INTERVAL_MS;
}

static void close_pending(cn_pending_conn_t *pend)
{
    if (pend->fd >= 0) {
        close(pend->fd);
        pend->fd = -1;
    }
    pend->in_len = 0;
    pend->out_len = 0;
    pend->hs_state = PEND_WAIT_INIT;
}

static bool enqueue_frame(uint8_t *out_buf, size_t *out_len, size_t cap,
                          uint16_t type, const void *payload, size_t len)
{
    if (len > CN_NET_MAX_PAYLOAD)
        return false;
    size_t total = CN_NET_HEADER_LEN + len;
    if (cap - *out_len < total)
        return false;

    uint32_t net_len  = htonl((uint32_t)len);
    uint16_t net_type = htons(type);
    uint16_t net_res  = 0;

    uint8_t *dest = out_buf + *out_len;
    memcpy(dest,     &net_len,  4);
    memcpy(dest + 4, &net_type, 2);
    memcpy(dest + 6, &net_res,  2);
    if (len > 0 && payload)
        memcpy(dest + CN_NET_HEADER_LEN, payload, len);

    *out_len += total;
    return true;
}

static bool enqueue_to_peer(cn_peer_conn_t *p, uint16_t type, const void *payload, size_t len)
{
    return enqueue_frame(p->out_buf, &p->out_len, sizeof(p->out_buf), type, payload, len);
}

static bool enqueue_to_pending(cn_pending_conn_t *pend, uint16_t type, const void *payload, size_t len)
{
    return enqueue_frame(pend->out_buf, &pend->out_len, sizeof(pend->out_buf), type, payload, len);
}

static bool flush_out(int fd, uint8_t *out_buf, size_t *out_len)
{
    if (*out_len == 0)
        return true;
    ssize_t sent = send(fd, out_buf, *out_len, 0);
    if (sent > 0) {
        size_t rem = *out_len - (size_t)sent;
        if (rem > 0)
            memmove(out_buf, out_buf + sent, rem);
        *out_len = rem;
        return true;
    }
    if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
        return true;
    return false;
}

static void send_hello_init(cn_net_t *net, cn_peer_conn_t *p)
{
    uint8_t buf[SC_HELLO_INIT_LEN];
    uint8_t my_pubkey[SC_ED25519_PUBKEY_LEN];

    if (crypto_get_pubkey(net->my_keypair, my_pubkey) != SC_OK) {
        close_peer(p, "cannot get own pubkey");
        return;
    }

    uint32_t my_id_net = htonl((uint32_t)net->my_connector_id);
    memcpy(buf,     &my_id_net, 4);
    memcpy(buf + 4, my_pubkey, SC_ED25519_PUBKEY_LEN);

    if (!enqueue_to_peer(p, CN_MSG_HELLO_INIT, buf, sizeof(buf))) {
        close_peer(p, "hello_init enqueue failed");
        return;
    }
    p->state = PEER_HS_INIT_SENT;
}

static void handle_hello_chal(cn_net_t *net, cn_peer_conn_t *p,
                              const uint8_t *payload, size_t len)
{
    if (len != SC_HELLO_CHAL_LEN) {
        close_peer(p, "bad HELLO_CHAL length");
        return;
    }
    const uint8_t *nonce       = payload;
    const uint8_t *peer_pubkey = payload + SC_NONCE_LEN;
    const uint8_t *peer_sig    = payload + SC_NONCE_LEN + SC_ED25519_PUBKEY_LEN;

    if (p->has_pubkey && memcmp(peer_pubkey, p->pubkey, SC_ED25519_PUBKEY_LEN) != 0) {
        close_peer(p, "pubkey mismatch against pinned config");
        return;
    }

    sc_keypair_t *peer_kp = NULL;
    if (crypto_pubkey_from_raw(&peer_kp, peer_pubkey) != SC_OK) {
        close_peer(p, "cannot build peer pubkey handle");
        return;
    }

    sc_err_t vrc = crypto_verify(peer_kp, nonce, SC_NONCE_LEN, peer_sig);
    crypto_keypair_free(peer_kp);

    if (vrc != SC_OK) {
        close_peer(p, "HELLO_CHAL signature invalid");
        return;
    }

    memcpy(p->handshake_nonce, nonce, SC_NONCE_LEN);

    uint8_t my_sig[SC_ED25519_SIG_LEN];
    if (crypto_sign(net->my_keypair, nonce, SC_NONCE_LEN, my_sig) != SC_OK) {
        close_peer(p, "HELLO_RESP sign failed");
        return;
    }
    if (!enqueue_to_peer(p, CN_MSG_HELLO_RESP, my_sig, sizeof(my_sig))) {
        close_peer(p, "HELLO_RESP enqueue failed");
        return;
    }

    p->state = PEER_CONNECTED;
    log_eventf(LOG_INFO, "cn_net", "peer_authenticated", "peer=%d dir=outbound", p->peer_id);
}

static void handle_pending_hello_init(cn_net_t *net, cn_pending_conn_t *pend,
                                      const uint8_t *payload, size_t len)
{
    if (len != SC_HELLO_INIT_LEN) {
        close_pending(pend);
        return;
    }
    uint32_t sender_id_net;
    memcpy(&sender_id_net, payload, 4);
    int sender_id = (int)ntohl(sender_id_net);
    const uint8_t *presented_pubkey = payload + 4;

    cn_peer_conn_t *p = find_peer(net, sender_id);
    if (!p) {
        close_pending(pend);
        return;
    }

    if (p->has_pubkey && memcmp(presented_pubkey, p->pubkey, SC_ED25519_PUBKEY_LEN) != 0) {
        close_pending(pend);
        return;
    }

    pend->claimed_id = sender_id;
    pend->hs_state   = PEND_WAIT_RESP;

    if (crypto_rand_bytes(pend->nonce, SC_NONCE_LEN) != SC_OK) {
        close_pending(pend);
        return;
    }

    uint8_t my_pubkey[SC_ED25519_PUBKEY_LEN];
    uint8_t my_sig[SC_ED25519_SIG_LEN];
    if (crypto_get_pubkey(net->my_keypair, my_pubkey) != SC_OK ||
        crypto_sign(net->my_keypair, pend->nonce, SC_NONCE_LEN, my_sig) != SC_OK) {
        close_pending(pend);
        return;
    }

    uint8_t chal[SC_HELLO_CHAL_LEN];
    memcpy(chal, pend->nonce, SC_NONCE_LEN);
    memcpy(chal + SC_NONCE_LEN, my_pubkey, SC_ED25519_PUBKEY_LEN);
    memcpy(chal + SC_NONCE_LEN + SC_ED25519_PUBKEY_LEN, my_sig, SC_ED25519_SIG_LEN);

    if (!enqueue_to_pending(pend, CN_MSG_HELLO_CHAL, chal, sizeof(chal))) {
        close_pending(pend);
        return;
    }
}

static void handle_pending_hello_resp(cn_net_t *net, cn_pending_conn_t *pend,
                                      const uint8_t *payload, size_t len)
{
    if (len != SC_HELLO_RESP_LEN) {
        close_pending(pend);
        return;
    }
    const uint8_t *resp_sig = payload;
    cn_peer_conn_t *p = find_peer(net, pend->claimed_id);
    if (!p) {
        close_pending(pend);
        return;
    }

    sc_keypair_t *peer_kp = NULL;
    if (crypto_pubkey_from_raw(&peer_kp, p->pubkey) != SC_OK) {
        close_pending(pend);
        return;
    }

    sc_err_t rc = crypto_verify(peer_kp, pend->nonce, SC_NONCE_LEN, resp_sig);
    crypto_keypair_free(peer_kp);

    if (rc != SC_OK) {
        close_pending(pend);
        return;
    }

    /* Close old connection if any */
    if (p->fd >= 0) {
        close(p->fd);
    }

    /* Promote to peer slot */
    p->fd = pend->fd;
    p->state = PEER_CONNECTED;
    p->in_len = pend->in_len;
    memcpy(p->in_buf, pend->in_buf, pend->in_len);
    p->out_len = pend->out_len;
    memcpy(p->out_buf, pend->out_buf, pend->out_len);

    pend->fd = -1;
    close_pending(pend);

    log_eventf(LOG_INFO, "cn_net", "peer_authenticated", "peer=%d dir=inbound", p->peer_id);
}

static void start_connect(cn_peer_conn_t *p)
{
    p->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (p->fd < 0) {
        p->next_reconnect_ms = get_now_ms() + RECONNECT_INTERVAL_MS;
        return;
    }
    set_nonblocking(p->fd);

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(p->port);
    inet_pton(AF_INET, p->host, &sa.sin_addr);

    int rc = connect(p->fd, (struct sockaddr *)&sa, sizeof(sa));
    if (rc == 0) {
        p->state = PEER_CONNECTING;
    } else if (errno == EINPROGRESS) {
        p->state = PEER_CONNECTING;
    } else {
        close_peer(p, "connect immediate error");
    }
}

sc_err_t cn_net_init(cn_net_t **net_out, const cn_config_t *cfg,
                     const sc_keypair_t *my_kp,
                     cn_net_msg_cb msg_cb, void *user,
                     char *errbuf, size_t errlen)
{
    if (!net_out || !cfg || !my_kp) {
        if (errbuf && errlen)
            snprintf(errbuf, errlen, "null argument");
        return SC_ERR_INVALID;
    }

    cn_net_t *net = calloc(1, sizeof(*net));
    if (!net)
        return SC_ERR_IO;

    net->my_connector_id = cfg->connector_id;
    net->my_keypair      = my_kp;
    net->msg_cb          = msg_cb;
    net->user_data       = user;
    net->listen_fd       = -1;

    for (size_t i = 0; i < MAX_PENDING_INBOUND; i++)
        net->pending[i].fd = -1;

    /* Setup listener */
    if (cfg->listen_port > 0) {
        net->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (net->listen_fd < 0) {
            if (errbuf && errlen)
                snprintf(errbuf, errlen, "socket: %s", strerror(errno));
            free(net);
            return SC_ERR_IO;
        }

        int one = 1;
        setsockopt(net->listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        set_nonblocking(net->listen_fd);

        struct sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_port   = htons(cfg->listen_port);
        sa.sin_addr.s_addr = htonl(INADDR_ANY);

        if (bind(net->listen_fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
            if (errbuf && errlen)
                snprintf(errbuf, errlen, "bind port %u: %s", cfg->listen_port, strerror(errno));
            close(net->listen_fd);
            free(net);
            return SC_ERR_IO;
        }

        if (listen(net->listen_fd, 16) != 0) {
            if (errbuf && errlen)
                snprintf(errbuf, errlen, "listen: %s", strerror(errno));
            close(net->listen_fd);
            free(net);
            return SC_ERR_IO;
        }
    }

    /* Populate peers */
    for (size_t i = 0; i < cfg->peer_count && i < CN_MAX_PEERS; i++) {
        cn_peer_conn_t *p = &net->peers[net->peer_count++];
        p->peer_id = cfg->peers[i].id;
        snprintf(p->host, sizeof(p->host), "%s", cfg->peers[i].host);
        p->port = cfg->peers[i].port;
        p->has_pubkey = cfg->peers[i].has_pubkey;
        if (p->has_pubkey)
            memcpy(p->pubkey, cfg->peers[i].pubkey, SC_ED25519_PUBKEY_LEN);
        p->fd = -1;
        p->state = PEER_DISCONNECTED;
        p->is_target = (cfg->connector_id < p->peer_id);
    }

    *net_out = net;
    return SC_OK;
}

void cn_net_shutdown(cn_net_t *net)
{
    if (!net)
        return;

    if (net->listen_fd >= 0) {
        close(net->listen_fd);
        net->listen_fd = -1;
    }

    for (size_t i = 0; i < net->peer_count; i++) {
        if (net->peers[i].fd >= 0) {
            close(net->peers[i].fd);
            net->peers[i].fd = -1;
        }
    }

    for (size_t i = 0; i < MAX_PENDING_INBOUND; i++) {
        if (net->pending[i].fd >= 0) {
            close(net->pending[i].fd);
            net->pending[i].fd = -1;
        }
    }

    free(net);
}

sc_err_t cn_net_poll_step(cn_net_t *net, int timeout_ms)
{
    if (!net)
        return SC_ERR_INVALID;

    int64_t now = get_now_ms();

    /* Try connecting to targets */
    for (size_t i = 0; i < net->peer_count; i++) {
        cn_peer_conn_t *p = &net->peers[i];
        if (p->is_target && p->state == PEER_DISCONNECTED && now >= p->next_reconnect_ms) {
            start_connect(p);
        }
    }

    struct pollfd pfds[1 + CN_MAX_PEERS + MAX_PENDING_INBOUND];
    int pfd_types[1 + CN_MAX_PEERS + MAX_PENDING_INBOUND];
    size_t pfd_indices[1 + CN_MAX_PEERS + MAX_PENDING_INBOUND];
    size_t npfd = 0;

    /* 0: listener */
    if (net->listen_fd >= 0) {
        pfds[npfd].fd = net->listen_fd;
        pfds[npfd].events = POLLIN;
        pfds[npfd].revents = 0;
        pfd_types[npfd] = 0;
        npfd++;
    }

    /* Peers */
    for (size_t i = 0; i < net->peer_count; i++) {
        cn_peer_conn_t *p = &net->peers[i];
        if (p->fd >= 0) {
            pfds[npfd].fd = p->fd;
            pfds[npfd].events = POLLIN;
            if (p->state == PEER_CONNECTING || p->out_len > 0)
                pfds[npfd].events |= POLLOUT;
            pfds[npfd].revents = 0;
            pfd_types[npfd] = 1;
            pfd_indices[npfd] = i;
            npfd++;
        }
    }

    /* Pending inbound */
    for (size_t i = 0; i < MAX_PENDING_INBOUND; i++) {
        cn_pending_conn_t *pend = &net->pending[i];
        if (pend->fd >= 0) {
            pfds[npfd].fd = pend->fd;
            pfds[npfd].events = POLLIN;
            if (pend->out_len > 0)
                pfds[npfd].events |= POLLOUT;
            pfds[npfd].revents = 0;
            pfd_types[npfd] = 2;
            pfd_indices[npfd] = i;
            npfd++;
        }
    }

    int rc = poll(pfds, (nfds_t)npfd, timeout_ms);
    if (rc <= 0)
        return SC_OK;

    for (size_t k = 0; k < npfd; k++) {
        short rev = pfds[k].revents;
        if (rev == 0)
            continue;

        if (pfd_types[k] == 0) {
            /* Listener */
            if (rev & POLLIN) {
                int cfd = accept(net->listen_fd, NULL, NULL);
                if (cfd >= 0) {
                    set_nonblocking(cfd);
                    bool placed = false;
                    for (size_t i = 0; i < MAX_PENDING_INBOUND; i++) {
                        if (net->pending[i].fd < 0) {
                            close_pending(&net->pending[i]);
                            net->pending[i].fd = cfd;
                            placed = true;
                            break;
                        }
                    }
                    if (!placed)
                        close(cfd);
                }
            }
        } else if (pfd_types[k] == 1) {
            /* Peer */
            cn_peer_conn_t *p = &net->peers[pfd_indices[k]];
            if (rev & (POLLERR | POLLHUP | POLLNVAL)) {
                close_peer(p, "poll error");
                continue;
            }

            if (p->state == PEER_CONNECTING && (rev & POLLOUT)) {
                int err = 0;
                socklen_t len = sizeof(err);
                getsockopt(p->fd, SOL_SOCKET, SO_ERROR, &err, &len);
                if (err == 0) {
                    send_hello_init(net, p);
                } else {
                    close_peer(p, "connection refused");
                    continue;
                }
            }

            if (rev & POLLOUT) {
                if (!flush_out(p->fd, p->out_buf, &p->out_len)) {
                    close_peer(p, "flush error");
                    continue;
                }
            }

            if (rev & POLLIN) {
                ssize_t n = recv(p->fd, p->in_buf + p->in_len, sizeof(p->in_buf) - p->in_len, 0);
                if (n <= 0) {
                    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
                        /* ok */
                    } else {
                        close_peer(p, n == 0 ? "peer closed" : "recv error");
                        continue;
                    }
                } else {
                    p->in_len += (size_t)n;
                    /* Parse frames */
                    while (p->in_len >= CN_NET_HEADER_LEN) {
                        uint32_t net_len;
                        uint16_t net_type;
                        memcpy(&net_len,  p->in_buf,     4);
                        memcpy(&net_type, p->in_buf + 4, 2);
                        uint32_t payload_len = ntohl(net_len);
                        uint16_t msg_type    = ntohs(net_type);

                        if (payload_len > CN_NET_MAX_PAYLOAD) {
                            close_peer(p, "frame too large");
                            break;
                        }

                        size_t frame_total = CN_NET_HEADER_LEN + payload_len;
                        if (p->in_len < frame_total)
                            break;

                        const uint8_t *payload = p->in_buf + CN_NET_HEADER_LEN;

                        if (p->state == PEER_HS_INIT_SENT && msg_type == CN_MSG_HELLO_CHAL) {
                            handle_hello_chal(net, p, payload, payload_len);
                        } else if (p->state == PEER_CONNECTED) {
                            if (msg_type == CN_MSG_PING) {
                                enqueue_to_peer(p, CN_MSG_PONG, NULL, 0);
                            } else if (msg_type == CN_MSG_PONG) {
                                /* pong received */
                            } else if (net->msg_cb) {
                                net->msg_cb(p->peer_id, msg_type, payload, payload_len, net->user_data);
                            }
                        }

                        size_t rem = p->in_len - frame_total;
                        if (rem > 0)
                            memmove(p->in_buf, p->in_buf + frame_total, rem);
                        p->in_len = rem;
                    }
                }
            }
        } else if (pfd_types[k] == 2) {
            /* Pending inbound */
            cn_pending_conn_t *pend = &net->pending[pfd_indices[k]];
            if (rev & (POLLERR | POLLHUP | POLLNVAL)) {
                close_pending(pend);
                continue;
            }

            if (rev & POLLOUT) {
                if (!flush_out(pend->fd, pend->out_buf, &pend->out_len)) {
                    close_pending(pend);
                    continue;
                }
            }

            if (rev & POLLIN) {
                ssize_t n = recv(pend->fd, pend->in_buf + pend->in_len,
                                 sizeof(pend->in_buf) - pend->in_len, 0);
                if (n <= 0) {
                    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
                        /* ok */
                    } else {
                        close_pending(pend);
                        continue;
                    }
                } else {
                    pend->in_len += (size_t)n;
                    while (pend->in_len >= CN_NET_HEADER_LEN) {
                        uint32_t net_len;
                        uint16_t net_type;
                        memcpy(&net_len,  pend->in_buf,     4);
                        memcpy(&net_type, pend->in_buf + 4, 2);
                        uint32_t payload_len = ntohl(net_len);
                        uint16_t msg_type    = ntohs(net_type);

                        if (payload_len > CN_NET_MAX_PAYLOAD) {
                            close_pending(pend);
                            break;
                        }

                        size_t frame_total = CN_NET_HEADER_LEN + payload_len;
                        if (pend->in_len < frame_total)
                            break;

                        const uint8_t *payload = pend->in_buf + CN_NET_HEADER_LEN;

                        if (pend->hs_state == PEND_WAIT_INIT && msg_type == CN_MSG_HELLO_INIT) {
                            handle_pending_hello_init(net, pend, payload, payload_len);
                        } else if (pend->hs_state == PEND_WAIT_RESP && msg_type == CN_MSG_HELLO_RESP) {
                            handle_pending_hello_resp(net, pend, payload, payload_len);
                            break; /* pend promoted or closed */
                        }

                        size_t rem = pend->in_len - frame_total;
                        if (rem > 0)
                            memmove(pend->in_buf, pend->in_buf + frame_total, rem);
                        pend->in_len = rem;
                    }
                }
            }
        }
    }

    return SC_OK;
}

sc_err_t cn_net_send(cn_net_t *net, int peer_id, uint16_t type,
                     const void *payload, size_t len)
{
    if (!net)
        return SC_ERR_INVALID;

    cn_peer_conn_t *p = find_peer(net, peer_id);
    if (!p || p->state != PEER_CONNECTED)
        return SC_ERR_NOT_FOUND;

    if (!enqueue_to_peer(p, type, payload, len))
        return SC_ERR_IO;

    return SC_OK;
}

sc_err_t cn_net_broadcast(cn_net_t *net, uint16_t type,
                           const void *payload, size_t len)
{
    if (!net)
        return SC_ERR_INVALID;

    for (size_t i = 0; i < net->peer_count; i++) {
        if (net->peers[i].state == PEER_CONNECTED) {
            enqueue_to_peer(&net->peers[i], type, payload, len);
        }
    }

    return SC_OK;
}

bool cn_net_is_connected(const cn_net_t *net, int peer_id)
{
    if (!net)
        return false;
    for (size_t i = 0; i < net->peer_count; i++) {
        if (net->peers[i].peer_id == peer_id && net->peers[i].state == PEER_CONNECTED)
            return true;
    }
    return false;
}

size_t cn_net_connected_count(const cn_net_t *net)
{
    if (!net)
        return 0;
    size_t count = 0;
    for (size_t i = 0; i < net->peer_count; i++) {
        if (net->peers[i].state == PEER_CONNECTED)
            count++;
    }
    return count;
}
