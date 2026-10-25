/* sc_wallet.c - Development tool: sign one ordinary transaction and submit it to a chain node.
 *
 * Used to create real traffic on a dev network (ordinary same-chain transactions, or a
 * cross-chain initiation by sending to the chain's bridge escrow pubkey). It authenticates
 * to the chain node with the same key it signs with, so that key's pubkey must be pinned
 * in the chain's network.conf (the dev network generator reserves a wallet slot for this).
 * The private key is read from a file; it is never printed or logged.
 *
 * Usage: sc_wallet --host H --port P --node-id N --node-pubkey HEX --key KEY.pem
 *                  --to RECIPIENT_HEX --amount N [--fee N] --nonce N
 */
#define _POSIX_C_SOURCE 200809L
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "cn_chain.h"
#include "../../src/log.h"

static bool parse_u64(const char *s, uint64_t *out)
{
    char *end = NULL;
    if (!s || !*s || *s == '-') return false;
    *out = strtoull(s, &end, 10);
    return end && *end == '\0';
}

static int64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000L;
}

int main(int argc, char **argv)
{
    const char *host = "127.0.0.1", *key = NULL, *to = NULL, *npub = NULL;
    uint64_t port = 0, node_id = 0, amount = 0, fee = 1, nonce = 0;
    bool have_amount = false, have_nonce = false;
    for (int i = 1; i + 1 < argc; i += 2) {
        const char *k = argv[i], *v = argv[i + 1];
        if (!strcmp(k, "--host")) host = v;
        else if (!strcmp(k, "--port")) { if (!parse_u64(v, &port)) goto usage; }
        else if (!strcmp(k, "--node-id")) { if (!parse_u64(v, &node_id)) goto usage; }
        else if (!strcmp(k, "--node-pubkey")) npub = v;
        else if (!strcmp(k, "--key")) key = v;
        else if (!strcmp(k, "--to")) to = v;
        else if (!strcmp(k, "--amount")) { if (!parse_u64(v, &amount)) goto usage; have_amount = true; }
        else if (!strcmp(k, "--fee")) { if (!parse_u64(v, &fee)) goto usage; }
        else if (!strcmp(k, "--nonce")) { if (!parse_u64(v, &nonce)) goto usage; have_nonce = true; }
        else goto usage;
    }
    if (!key || !to || !npub || !port || port > 65535 || !have_amount || !have_nonce) goto usage;

    log_init(-1);
    cn_chain_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.host, sizeof(cfg.host), "%s", host);
    cfg.port = (uint16_t)port;
    cfg.our_node_id = (int)node_id;
    if (!crypto_hex_decode(npub, cfg.pubkey, 32)) { fprintf(stderr, "bad --node-pubkey\n"); return 2; }
    cfg.has_pubkey = true;

    uint8_t recipient[32];
    if (!crypto_hex_decode(to, recipient, 32)) { fprintf(stderr, "bad --to (64 hex chars)\n"); return 2; }

    char err[256] = "";
    sc_keypair_t *kp = NULL;
    if (crypto_load_privkey(&kp, key, err, sizeof(err)) != SC_OK) { fprintf(stderr, "cannot load key: %s\n", err); return 1; }

    sc_tx_t tx;
    if (tx_create(&tx, kp, recipient, amount, fee, nonce) != SC_OK) { fprintf(stderr, "tx_create failed\n"); return 1; }

    cn_chain_conn_t *conn = NULL;
    (void)cn_chain_connect(&conn, &cfg, kp, NULL, NULL, NULL, err, sizeof(err));
    int rc = 1;
    int64_t deadline = now_ms() + 5000;
    while (conn && now_ms() < deadline && !cn_chain_is_connected(conn)) cn_chain_poll_step(conn, 20);
    if (conn && cn_chain_is_connected(conn) && cn_chain_submit_tx(conn, &tx) == SC_OK) {
        int64_t flush = now_ms() + 300;
        while (now_ms() < flush) cn_chain_poll_step(conn, 20);   /* let the frame leave the buffer */
        char h[65];
        crypto_hex_encode(tx.hash, 32, h);
        printf("submitted tx_hash=%s (submission only; this does not mean the chain accepted or finalized it)\n", h);
        rc = 0;
    } else {
        fprintf(stderr, "could not connect/authenticate to %s:%u within 5s\n", host, (unsigned)port);
    }
    if (conn) cn_chain_close(conn);
    crypto_keypair_free(kp);
    return rc;
usage:
    fprintf(stderr, "usage: sc_wallet --host H --port P --node-id N --node-pubkey HEX --key KEY.pem --to HEX --amount N [--fee N] --nonce N\n");
    return 2;
}
