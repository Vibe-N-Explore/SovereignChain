/* injector.c - Adversarial network injector for SovereignChain.
 *
 * Phase 9: Security and integration testing.
 *
 * Usage:
 *   injector --impostor <target_host> <target_port> <claimed_id>
 *   injector --oversized <target_host> <target_port>
 */
#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "crypto.h"
#include "net.h"

static int connect_to(const char *host, int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    inet_pton(AF_INET, host, &sa.sin_addr);

    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int main(int argc, char **argv)
{
    if (argc < 4) {
        fprintf(stderr, "usage: injector --impostor|--oversized <host> <port> [claimed_id]\n");
        return 2;
    }

    const char *mode = argv[1];
    const char *host = argv[2];
    int port = atoi(argv[3]);

    if (strcmp(mode, "--impostor") == 0) {
        int claimed_id = (argc >= 5) ? atoi(argv[4]) : 0;
        int fd = connect_to(host, port);
        if (fd < 0) {
            fprintf(stderr, "injector: connection to %s:%d failed\n", host, port);
            return 1;
        }

        /* Generate an unpinned rogue Ed25519 keypair */
        sc_keypair_t *rogue_kp = NULL;
        crypto_keygen(&rogue_kp);
        uint8_t rogue_pub[SC_ED25519_PUBKEY_LEN];
        crypto_get_pubkey(rogue_kp, rogue_pub);

        /* Send HELLO_REQ with claimed_id but unpinned rogue_pub */
        uint8_t payload[4 + SC_ED25519_PUBKEY_LEN];
        uint32_t id_net = htonl((uint32_t)claimed_id);
        memcpy(payload, &id_net, 4);
        memcpy(payload + 4, rogue_pub, SC_ED25519_PUBKEY_LEN);

        uint32_t net_len = htonl((uint32_t)sizeof(payload));
        uint16_t net_type = htons(1); /* MSG_TYPE_HELLO_REQ */
        uint16_t net_res = 0;

        uint8_t frame[SC_NET_HEADER_LEN + sizeof(payload)];
        memcpy(frame, &net_len, 4);
        memcpy(frame + 4, &net_type, 2);
        memcpy(frame + 6, &net_res, 2);
        memcpy(frame + SC_NET_HEADER_LEN, payload, sizeof(payload));

        send(fd, frame, sizeof(frame), 0);

        /* Read response: node must reject and close connection (EOF / recv 0) */
        uint8_t buf[256];
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        close(fd);
        crypto_keypair_free(rogue_kp);

        if (n <= 0) {
            printf("injector: target cleanly rejected impostor (connection closed)\n");
            return 0;
        } else {
            fprintf(stderr, "injector: target accepted impostor (vulnerability!)\n");
            return 1;
        }
    } else if (strcmp(mode, "--oversized") == 0) {
        int fd = connect_to(host, port);
        if (fd < 0) {
            fprintf(stderr, "injector: connection to %s:%d failed\n", host, port);
            return 1;
        }

        /* Send header claiming 1 MB frame (> 64 KB limit) */
        uint32_t net_len = htonl(1024 * 1024);
        uint16_t net_type = htons(4);
        uint16_t net_res = 0;

        uint8_t frame[SC_NET_HEADER_LEN];
        memcpy(frame, &net_len, 4);
        memcpy(frame + 4, &net_type, 2);
        memcpy(frame + 6, &net_res, 2);

        send(fd, frame, sizeof(frame), 0);

        uint8_t buf[256];
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        close(fd);

        if (n <= 0) {
            printf("injector: target cleanly dropped oversized frame\n");
            return 0;
        } else {
            fprintf(stderr, "injector: target kept connection open for oversized frame!\n");
            return 1;
        }
    }

    return 2;
}
