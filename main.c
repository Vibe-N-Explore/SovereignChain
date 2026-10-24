/* main.c - SovereignChain node process (Phase 1: foundation).
 *
 * Usage: node --network <network.conf> --config <node_N.conf>
 *
 * Phase 1 behaviour:
 *   1. load + validate the shared network file and this node's own file
 *   2. enforce the fixed topology (2 validators + 4 normal nodes)
 *   3. look up this node's role in the network file
 *   4. open (bind + listen on) this node's TCP port
 *   5. log "started", idle until SIGINT/SIGTERM, log "shutdown", exit 0
 *
 * No peer traffic, crypto or consensus exists yet.
 */
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

#define EXIT_USAGE 2
#define TOPOLOGY_VALIDATORS 2
#define TOPOLOGY_NORMALS    4

/* A signal handler may only do async-signal-safe things. Setting a
 * volatile sig_atomic_t is one of the few safe options, so the handler
 * just records the signal and the main loop does the real shutdown. */
static volatile sig_atomic_t g_stop_signal = 0;

static void on_signal(int sig) { g_stop_signal = sig; }

static void install_signal_handlers(void)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    /* Deliberately no SA_RESTART: we want nanosleep() to return early. */
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    /* Writing to a closed socket must return EPIPE, not kill the process.
     * Not needed yet, but every later phase relies on it. */
    signal(SIGPIPE, SIG_IGN);
}

static void usage(const char *prog)
{
    fprintf(stderr, "usage: %s --network <network.conf> --config <node.conf>\n",
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
    /* Allow quick restarts while old connections sit in TIME_WAIT. */
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

int main(int argc, char **argv)
{
    const char *net_path = NULL, *cfg_path = NULL;
    network_config_t net;
    node_config_t cfg;
    const node_info_t *me;
    char err[256];
    int listen_fd = -1;
    sc_err_t rc;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--network") == 0 && i + 1 < argc)
            net_path = argv[++i];
        else if (strcmp(argv[i], "--config") == 0 && i + 1 < argc)
            cfg_path = argv[++i];
        else {
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
    rc = config_load_network(net_path, &net, err, sizeof err);
    if (rc == SC_OK)
        rc = config_check_topology(&net, TOPOLOGY_VALIDATORS,
                                   TOPOLOGY_NORMALS, err, sizeof err);
    if (rc == SC_OK)
        rc = config_load_node(cfg_path, &cfg, err, sizeof err);
    if (rc != SC_OK) {
        log_eventf(LOG_ERROR, "config", "config_error", "code=%s detail=\"%s\"",
                   sc_err_str(rc), err);
        return EXIT_FAILURE;
    }

    me = config_find_node(&net, cfg.node_id);
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

    log_eventf(LOG_INFO, "main", "started", "role=%s host=%s port=%u peers=%zu",
               role_str(me->role), me->host, (unsigned)me->port,
               net.count - 1);

    /* Idle loop. Phase 2 replaces this sleep with poll() on the sockets. */
    while (!g_stop_signal) {
        struct timespec ts = {0, 100L * 1000L * 1000L}; /* 100 ms */
        nanosleep(&ts, NULL);
    }

    log_eventf(LOG_INFO, "main", "shutdown", "signal=%d", (int)g_stop_signal);
    close(listen_fd);
    return EXIT_SUCCESS;
}
