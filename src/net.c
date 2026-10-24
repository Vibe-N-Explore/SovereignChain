/* net.c - SovereignChain networking implementation (Phase 2: framed TCP). */
#define _POSIX_C_SOURCE 200809L

#include "net.h"

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

#include "log.h"

#define RECONNECT_INTERVAL_MS 1000
#define MAX_PENDING_INBOUND   8
#define BUF_SIZE              (SC_NET_HEADER_LEN + SC_NET_MAX_PAYLOAD)

typedef enum {
    PEER_DISCONNECTED = 0,
    PEER_CONNECTING,
    PEER_CONNECTED
} peer_state_t;

typedef struct {
    int          node_id;
    char         host[SC_MAX_HOST];
    uint16_t     port;
    bool         is_target;
    peer_state_t state;
    int          fd;
    int64_t      next_reconnect_ms;

    uint8_t      in_buf[BUF_SIZE];
    size_t       in_len;

    uint8_t      out_buf[BUF_SIZE];
    size_t       out_len;
} peer_conn_t;

typedef struct {
    int     fd;
    uint8_t in_buf[BUF_SIZE];
    size_t  in_len;
} pending_conn_t;

struct sc_net {
    const node_info_t *me;
    int               listen_fd;
    sc_net_msg_cb     msg_cb;
    void             *user_data;

    peer_conn_t       peers[SC_MAX_NODES];
    size_t            peer_count;

    pending_conn_t    pending[MAX_PENDING_INBOUND];
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

static peer_conn_t *find_peer_by_id(sc_net_t *net, int id)
{
    for (size_t i = 0; i < net->peer_count; i++) {
        if (net->peers[i].node_id == id)
            return &net->peers[i];
    }
    return NULL;
}

static void close_peer(sc_net_t *net, peer_conn_t *p, const char *reason)
{
    (void)net;
    if (p->fd >= 0) {
        log_eventf(LOG_INFO, "net", "peer_disconnected",
                   "peer=%d reason=\"%s\"", p->node_id, reason ? reason : "closed");
        close(p->fd);
        p->fd = -1;
    }
    p->state = PEER_DISCONNECTED;
    p->in_len = 0;
    p->out_len = 0;
    p->next_reconnect_ms = get_now_ms() + RECONNECT_INTERVAL_MS;
}

static void close_pending(pending_conn_t *pend)
{
    if (pend->fd >= 0) {
        close(pend->fd);
        pend->fd = -1;
    }
    pend->in_len = 0;
}

static sc_err_t enqueue_frame(peer_conn_t *p, uint16_t type,
                              const void *payload, size_t len)
{
    if (len > SC_NET_MAX_PAYLOAD)
        return SC_ERR_INVALID;

    size_t total = SC_NET_HEADER_LEN + len;
    if (sizeof(p->out_buf) - p->out_len < total) {
        log_eventf(LOG_WARN, "net", "out_buf_full", "peer=%d dropping msg", p->node_id);
        return SC_ERR_IO;
    }

    uint32_t net_len = htonl((uint32_t)len);
    uint16_t net_type = htons(type);
    uint16_t net_res = 0;

    uint8_t *dest = p->out_buf + p->out_len;
    memcpy(dest, &net_len, 4);
    memcpy(dest + 4, &net_type, 2);
    memcpy(dest + 6, &net_res, 2);
    if (len > 0 && payload)
        memcpy(dest + SC_NET_HEADER_LEN, payload, len);

    p->out_len += total;
    return SC_OK;
}

static void send_hello(sc_net_t *net, peer_conn_t *p)
{
    uint32_t my_id_net = htonl((uint32_t)net->me->id);
    enqueue_frame(p, MSG_TYPE_HELLO, &my_id_net, sizeof(my_id_net));
}

static void start_connect(sc_net_t *net, peer_conn_t *p)
{
    struct sockaddr_in sa;
    int fd;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        p->next_reconnect_ms = get_now_ms() + RECONNECT_INTERVAL_MS;
        return;
    }
    if (set_nonblocking(fd) != SC_OK) {
        close(fd);
        p->next_reconnect_ms = get_now_ms() + RECONNECT_INTERVAL_MS;
        return;
    }

    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons(p->port);
    if (inet_pton(AF_INET, p->host, &sa.sin_addr) != 1) {
        close(fd);
        p->next_reconnect_ms = get_now_ms() + RECONNECT_INTERVAL_MS;
        return;
    }

    p->fd = fd;
    p->state = PEER_CONNECTING;
    p->in_len = 0;
    p->out_len = 0;

    int rc = connect(fd, (struct sockaddr *)&sa, sizeof sa);
    if (rc == 0) {
        p->state = PEER_CONNECTED;
        log_eventf(LOG_INFO, "net", "peer_connected", "peer=%d dir=outbound", p->node_id);
        send_hello(net, p);
    } else if (errno == EINPROGRESS) {
        /* Async connect underway */
    } else {
        close(fd);
        p->fd = -1;
        p->state = PEER_DISCONNECTED;
        p->next_reconnect_ms = get_now_ms() + RECONNECT_INTERVAL_MS;
    }
}

static void process_frame(sc_net_t *net, int from_id, uint16_t type,
                          const uint8_t *payload, size_t len)
{
    if (type == MSG_TYPE_PING) {
        net_send(net, from_id, MSG_TYPE_PONG, payload, len);
    } else if (type == MSG_TYPE_HELLO) {
        /* Hello acknowledgment */
    } else {
        if (net->msg_cb)
            net->msg_cb(from_id, type, payload, len, net->user_data);
    }
}

static void drain_peer_in_buf(sc_net_t *net, peer_conn_t *p)
{
    while (p->in_len >= SC_NET_HEADER_LEN) {
        uint32_t net_len;
        uint16_t net_type;
        memcpy(&net_len, p->in_buf, 4);
        memcpy(&net_type, p->in_buf + 4, 2);

        uint32_t payload_len = ntohl(net_len);
        uint16_t type = ntohs(net_type);

        if (payload_len > SC_NET_MAX_PAYLOAD) {
            log_eventf(LOG_ERROR, "net", "frame_oversized",
                       "peer=%d len=%u max=%u", p->node_id, payload_len,
                       (unsigned)SC_NET_MAX_PAYLOAD);
            close_peer(net, p, "oversized frame");
            return;
        }

        size_t total_frame = SC_NET_HEADER_LEN + payload_len;
        if (p->in_len < total_frame)
            break;

        const uint8_t *payload = p->in_buf + SC_NET_HEADER_LEN;
        process_frame(net, p->node_id, type, payload, payload_len);

        size_t remaining = p->in_len - total_frame;
        if (remaining > 0)
            memmove(p->in_buf, p->in_buf + total_frame, remaining);
        p->in_len = remaining;
    }
}

static void handle_pending_read(sc_net_t *net, pending_conn_t *pend)
{
    ssize_t n = recv(pend->fd, pend->in_buf + pend->in_len,
                     sizeof(pend->in_buf) - pend->in_len, 0);
    if (n <= 0) {
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
            return;
        close_pending(pend);
        return;
    }
    pend->in_len += (size_t)n;

    if (pend->in_len >= SC_NET_HEADER_LEN) {
        uint32_t net_len;
        uint16_t net_type;
        memcpy(&net_len, pend->in_buf, 4);
        memcpy(&net_type, pend->in_buf + 4, 2);

        uint32_t payload_len = ntohl(net_len);
        uint16_t type = ntohs(net_type);

        if (payload_len > SC_NET_MAX_PAYLOAD || type != MSG_TYPE_HELLO) {
            close_pending(pend);
            return;
        }

        size_t total_frame = SC_NET_HEADER_LEN + payload_len;
        if (pend->in_len < total_frame)
            return;

        if (payload_len < 4) {
            close_pending(pend);
            return;
        }

        uint32_t sender_id_net;
        memcpy(&sender_id_net, pend->in_buf + SC_NET_HEADER_LEN, 4);
        int sender_id = (int)ntohl(sender_id_net);

        peer_conn_t *p = find_peer_by_id(net, sender_id);
        if (!p) {
            log_eventf(LOG_WARN, "net", "unknown_peer_hello", "node=%d", sender_id);
            close_pending(pend);
            return;
        }

        if (p->fd >= 0)
            close_peer(net, p, "replaced by new inbound");

        p->fd = pend->fd;
        p->state = PEER_CONNECTED;
        p->in_len = pend->in_len - total_frame;
        if (p->in_len > 0)
            memcpy(p->in_buf, pend->in_buf + total_frame, p->in_len);
        p->out_len = 0;

        pend->fd = -1;
        pend->in_len = 0;

        log_eventf(LOG_INFO, "net", "peer_connected", "peer=%d dir=inbound", p->node_id);
        send_hello(net, p);

        if (p->in_len >= SC_NET_HEADER_LEN)
            drain_peer_in_buf(net, p);
    }
}

sc_err_t net_init(sc_net_t **net_out, const network_config_t *topology,
                  const node_info_t *me, int listen_fd,
                  sc_net_msg_cb msg_cb, void *user,
                  char *errbuf, size_t errlen)
{
    (void)errbuf;
    (void)errlen;
    sc_net_t *net = calloc(1, sizeof(*net));
    if (!net)
        return SC_ERR_IO;

    net->me = me;
    net->listen_fd = listen_fd;
    net->msg_cb = msg_cb;
    net->user_data = user;

    set_nonblocking(listen_fd);

    size_t pcount = 0;
    for (size_t i = 0; i < topology->count; i++) {
        const node_info_t *ni = &topology->nodes[i];
        if (ni->id == me->id)
            continue;

        peer_conn_t *p = &net->peers[pcount++];
        p->node_id = ni->id;
        snprintf(p->host, sizeof(p->host), "%s", ni->host);
        p->port = ni->port;
        p->fd = -1;
        p->state = PEER_DISCONNECTED;
        p->is_target = (me->id < ni->id);
        p->next_reconnect_ms = 0;
    }
    net->peer_count = pcount;

    for (int i = 0; i < MAX_PENDING_INBOUND; i++) {
        net->pending[i].fd = -1;
        net->pending[i].in_len = 0;
    }

    *net_out = net;
    return SC_OK;
}

void net_shutdown(sc_net_t *net)
{
    if (!net)
        return;

    for (size_t i = 0; i < net->peer_count; i++) {
        if (net->peers[i].fd >= 0) {
            close(net->peers[i].fd);
            net->peers[i].fd = -1;
        }
    }
    for (int i = 0; i < MAX_PENDING_INBOUND; i++) {
        if (net->pending[i].fd >= 0) {
            close(net->pending[i].fd);
            net->pending[i].fd = -1;
        }
    }
    free(net);
}

sc_err_t net_send(sc_net_t *net, int target_node_id, uint16_t type,
                  const void *payload, size_t len)
{
    if (!net)
        return SC_ERR_INVALID;
    if (len > SC_NET_MAX_PAYLOAD)
        return SC_ERR_INVALID;

    if (target_node_id == SC_BROADCAST_ALL) {
        for (size_t i = 0; i < net->peer_count; i++) {
            peer_conn_t *p = &net->peers[i];
            if (p->state == PEER_CONNECTED)
                enqueue_frame(p, type, payload, len);
        }
        return SC_OK;
    }

    peer_conn_t *p = find_peer_by_id(net, target_node_id);
    if (!p)
        return SC_ERR_NOT_FOUND;
    if (p->state != PEER_CONNECTED)
        return SC_ERR_IO;

    return enqueue_frame(p, type, payload, len);
}

bool net_is_connected(const sc_net_t *net, int target_node_id)
{
    if (!net)
        return false;
    for (size_t i = 0; i < net->peer_count; i++) {
        if (net->peers[i].node_id == target_node_id)
            return net->peers[i].state == PEER_CONNECTED;
    }
    return false;
}

size_t net_connected_count(const sc_net_t *net)
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

sc_err_t net_poll_step(sc_net_t *net, int timeout_ms)
{
    if (!net)
        return SC_ERR_INVALID;

    int64_t now_ms = get_now_ms();

    for (size_t i = 0; i < net->peer_count; i++) {
        peer_conn_t *p = &net->peers[i];
        if (p->is_target && p->state == PEER_DISCONNECTED && now_ms >= p->next_reconnect_ms) {
            start_connect(net, p);
        }
    }

    struct pollfd fds[1 + SC_MAX_NODES + MAX_PENDING_INBOUND];
    int fd_map_type[1 + SC_MAX_NODES + MAX_PENDING_INBOUND];
    size_t fd_map_idx[1 + SC_MAX_NODES + MAX_PENDING_INBOUND];
    nfds_t nfds = 0;

    fds[nfds].fd = net->listen_fd;
    fds[nfds].events = POLLIN;
    fds[nfds].revents = 0;
    fd_map_type[nfds] = 0;
    fd_map_idx[nfds] = 0;
    nfds++;

    for (size_t i = 0; i < net->peer_count; i++) {
        peer_conn_t *p = &net->peers[i];
        if (p->fd >= 0) {
            fds[nfds].fd = p->fd;
            fds[nfds].events = POLLIN;
            if (p->state == PEER_CONNECTING || p->out_len > 0)
                fds[nfds].events |= POLLOUT;
            fds[nfds].revents = 0;
            fd_map_type[nfds] = 1;
            fd_map_idx[nfds] = i;
            nfds++;
        }
    }

    for (size_t i = 0; i < MAX_PENDING_INBOUND; i++) {
        if (net->pending[i].fd >= 0) {
            fds[nfds].fd = net->pending[i].fd;
            fds[nfds].events = POLLIN;
            fds[nfds].revents = 0;
            fd_map_type[nfds] = 2;
            fd_map_idx[nfds] = i;
            nfds++;
        }
    }

    int poll_rc = poll(fds, nfds, timeout_ms);
    if (poll_rc < 0) {
        if (errno == EINTR)
            return SC_OK;
        return SC_ERR_IO;
    }
    if (poll_rc == 0)
        return SC_OK;

    for (nfds_t i = 0; i < nfds; i++) {
        if (fds[i].revents == 0)
            continue;

        short rev = fds[i].revents;

        if (fd_map_type[i] == 0) {
            if (rev & POLLIN) {
                struct sockaddr_in client_sa;
                socklen_t client_len = sizeof(client_sa);
                int client_fd = accept(net->listen_fd, (struct sockaddr *)&client_sa, &client_len);
                if (client_fd >= 0) {
                    set_nonblocking(client_fd);
                    int slot = -1;
                    for (int k = 0; k < MAX_PENDING_INBOUND; k++) {
                        if (net->pending[k].fd < 0) {
                            slot = k;
                            break;
                        }
                    }
                    if (slot >= 0) {
                        net->pending[slot].fd = client_fd;
                        net->pending[slot].in_len = 0;
                    } else {
                        close(client_fd);
                    }
                }
            }
        } else if (fd_map_type[i] == 1) {
            peer_conn_t *p = &net->peers[fd_map_idx[i]];

            if (p->state == PEER_CONNECTING) {
                if (rev & (POLLOUT | POLLERR | POLLHUP)) {
                    int err = 0;
                    socklen_t elen = sizeof(err);
                    getsockopt(p->fd, SOL_SOCKET, SO_ERROR, &err, &elen);
                    if (err == 0) {
                        p->state = PEER_CONNECTED;
                        log_eventf(LOG_INFO, "net", "peer_connected",
                                   "peer=%d dir=outbound", p->node_id);
                        send_hello(net, p);
                    } else {
                        close_peer(net, p, "connect failed");
                        continue;
                    }
                }
            }

            if ((rev & POLLOUT) && p->state == PEER_CONNECTED && p->out_len > 0) {
                ssize_t sent = send(p->fd, p->out_buf, p->out_len, 0);
                if (sent > 0) {
                    size_t remaining = p->out_len - (size_t)sent;
                    if (remaining > 0)
                        memmove(p->out_buf, p->out_buf + sent, remaining);
                    p->out_len = remaining;
                } else if (sent < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                    close_peer(net, p, "send error");
                    continue;
                }
            }

            if ((rev & (POLLIN | POLLHUP | POLLERR)) && p->state == PEER_CONNECTED) {
                ssize_t n = recv(p->fd, p->in_buf + p->in_len,
                                 sizeof(p->in_buf) - p->in_len, 0);
                if (n > 0) {
                    p->in_len += (size_t)n;
                    drain_peer_in_buf(net, p);
                } else if (n == 0) {
                    close_peer(net, p, "peer closed");
                } else {
                    if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
                        close_peer(net, p, "recv error");
                }
            }
        } else if (fd_map_type[i] == 2) {
            pending_conn_t *pend = &net->pending[fd_map_idx[i]];
            if (rev & (POLLIN | POLLHUP | POLLERR)) {
                handle_pending_read(net, pend);
            }
        }
    }

    return SC_OK;
}
