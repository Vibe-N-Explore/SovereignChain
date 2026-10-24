/* main.c - SovereignChain node process (Phase 2: framed networking). */
#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "config.h"
#include "err.h"
#include "log.h"
#include "net.h"

#define EXIT_USAGE 2
#define TOPOLOGY_VALIDATORS 2
#define TOPOLOGY_NORMALS    4

static volatile sig_atomic_t g_stop_signal = 0;

static void on_signal(int sig) { g_stop_signal = sig; }

static void install_signal_handlers(void)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);
}

static void usage(const char *prog)
{
    fprintf(stderr, "usage: %s --network <network.conf> --config <node.conf> "
                    "[--send-test <target_id> <message>]\n",
            prog);
}

static sc_err_t open_listener(const node_info_t *me, int *fd_out, char *errbuf,
                              size_t errlen)
{
    struct sockaddr_in sa;
    int fd, one = 1;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        snprintf(errbuf, errlen, "socket: %s", strerror(errno));
        return SC_ERR_IO;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) != 0) {
        snprintf(errbuf, errlen, "setsockopt: %s", strerror(errno));
        close(fd);
        return SC_ERR_IO;
    }
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons(me->port);
    if (inet_pton(AF_INET, me->host, &sa.sin_addr) != 1) {
        snprintf(errbuf, errlen, "bad address %s", me->host);
        close(fd);
        return SC_ERR_INVALID;
    }
    if (bind(fd, (struct sockaddr *)&sa, sizeof sa) != 0) {
        snprintf(errbuf, errlen, "bind %s:%u: %s", me->host,
                 (unsigned)me->port, strerror(errno));
        close(fd);
        return SC_ERR_IO;
    }
    if (listen(fd, 16) != 0) {
        snprintf(errbuf, errlen, "listen: %s", strerror(errno));
        close(fd);
        return SC_ERR_IO;
    }
    *fd_out = fd;
    return SC_OK;
}

static void on_message(int from_node_id, uint16_t type,
                       const uint8_t *payload, size_t len, void *user)
{
    (void)user;
    if (type == MSG_TYPE_TEST) {
        char safe_payload[256];
        size_t cpy = len < sizeof(safe_payload) - 1 ? len : sizeof(safe_payload) - 1;
        memcpy(safe_payload, payload, cpy);
        safe_payload[cpy] = '\0';

        log_eventf(LOG_INFO, "net", "recv_test",
                   "from=%d len=%zu payload=\"%s\"", from_node_id, len, safe_payload);
    }
}

int main(int argc, char **argv)
{
    const char *net_path = NULL, *cfg_path = NULL;
    int test_target_id = -1;
    const char *test_msg = NULL;
    bool test_sent = false;

    network_config_t net_cfg;
    node_config_t cfg;
    const node_info_t *me;
    char err[256];
    int listen_fd = -1;
    sc_net_t *net = NULL;
    sc_err_t rc;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--network") == 0 && i + 1 < argc)
            net_path = argv[++i];
        else if (strcmp(argv[i], "--config") == 0 && i + 1 < argc)
            cfg_path = argv[++i];
        else if (strcmp(argv[i], "--send-test") == 0 && i + 2 < argc) {
            test_target_id = atoi(argv[++i]);
            test_msg = argv[++i];
        } else {
            usage(argv[0]);
            return EXIT_USAGE;
        }
    }
    if (!net_path || !cfg_path) {
        usage(argv[0]);
        return EXIT_USAGE;
    }

    log_init(-1);

    err[0] = '\0';
    rc = config_load_network(net_path, &net_cfg, err, sizeof err);
    if (rc == SC_OK)
        rc = config_check_topology(&net_cfg, TOPOLOGY_VALIDATORS,
                                   TOPOLOGY_NORMALS, err, sizeof err);
    if (rc == SC_OK)
        rc = config_load_node(cfg_path, &cfg, err, sizeof err);
    if (rc != SC_OK) {
        log_eventf(LOG_ERROR, "config", "config_error", "code=%s detail=\"%s\"",
                   sc_err_str(rc), err);
        return EXIT_FAILURE;
    }

    me = config_find_node(&net_cfg, cfg.node_id);
    if (!me) {
        log_eventf(LOG_ERROR, "config", "config_error",
                   "code=%s detail=\"node_id %d is not in %s\"",
                   sc_err_str(SC_ERR_NOT_FOUND), cfg.node_id, net_path);
        return EXIT_FAILURE;
    }
    log_init(me->id);

    install_signal_handlers();

    rc = open_listener(me, &listen_fd, err, sizeof err);
    if (rc != SC_OK) {
        log_eventf(LOG_ERROR, "net", "listen_error", "code=%s detail=\"%s\"",
                   sc_err_str(rc), err);
        return EXIT_FAILURE;
    }

    rc = net_init(&net, &net_cfg, me, listen_fd, on_message, NULL, err, sizeof err);
    if (rc != SC_OK) {
        log_eventf(LOG_ERROR, "net", "init_error", "code=%s detail=\"%s\"",
                   sc_err_str(rc), err);
        close(listen_fd);
        return EXIT_FAILURE;
    }

    log_eventf(LOG_INFO, "main", "started", "role=%s host=%s port=%u peers=%zu",
               role_str(me->role), me->host, (unsigned)me->port,
               net_cfg.count - 1);

    while (!g_stop_signal) {
        rc = net_poll_step(net, 100);
        if (rc != SC_OK && rc != SC_ERR_IO) {
            log_eventf(LOG_ERROR, "net", "poll_error", "code=%s", sc_err_str(rc));
            break;
        }

        if (test_target_id >= 0 && !test_sent && net_is_connected(net, test_target_id)) {
            size_t msg_len = strlen(test_msg);
            sc_err_t s_rc = net_send(net, test_target_id, MSG_TYPE_TEST, test_msg, msg_len);
            if (s_rc == SC_OK) {
                log_eventf(LOG_INFO, "net", "sent_test",
                           "to=%d len=%zu payload=\"%s\"", test_target_id, msg_len, test_msg);
                test_sent = true;
            }
        }
    }

    log_eventf(LOG_INFO, "main", "shutdown", "signal=%d", (int)g_stop_signal);
    net_shutdown(net);
    close(listen_fd);
    return EXIT_SUCCESS;
}
