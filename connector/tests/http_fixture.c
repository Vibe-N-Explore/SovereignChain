/* http_fixture.c - writes real, correctly signed records into a connector data_dir
 * using the connector's own store/activity/transfer code. Used only by
 * tests/http_smoke.sh; never linked into the daemon.
 * Usage: http_fixture <data_dir> <conn_key_out>
 */
#include <stdio.h>
#include <string.h>
#include "cn_activity.h"
#include "cn_store.h"
#include "cn_transfer.h"

int main(int argc, char **argv)
{
    if (argc != 3) return 2;
    sc_keypair_t *conn, *alice, *bob;
    if (crypto_keygen(&conn) || crypto_keygen(&alice) || crypto_keygen(&bob)) return 1;
    if (crypto_save_privkey(conn, argv[2]) != SC_OK) return 1;
    uint8_t bobpub[32], bridge[32] = {0xaa};
    crypto_get_pubkey(bob, bobpub);
    cn_store_t *st = NULL;
    if (cn_store_open(&st, argv[1]) != SC_OK) return 1;
    uint8_t vertex[32] = {0};
    sc_tx_t tx;
    for (int i = 0; i < 5; i++) {              /* 3 on chain A, 2 on chain B */
        uint8_t chain = (i < 3) ? CN_CHAIN_A : CN_CHAIN_B;
        if (tx_create(&tx, alice, bobpub, 100u + (uint64_t)i, 1, (uint64_t)i) != SC_OK) return 1;
        cn_activity_record_t rec;
        if (cn_activity_create(&rec, chain, &tx, 0, vertex, i == 0 ? CN_STATUS_FINALIZED : CN_STATUS_VERIFIED, conn) != SC_OK) return 1;
        if (cn_store_add_activity(st, &rec) != SC_OK) return 1;
    }
    /* one cross-chain transfer: alice -> bridge escrow on chain A */
    if (tx_create(&tx, alice, bridge, 1000, 1, 99) != SC_OK) return 1;
    cn_rate_t rate = { .rate_num = 3, .rate_den = 2, .version = 1 };
    cn_transfer_t x;
    if (cn_transfer_create(&x, CN_CHAIN_A, &tx, &rate) != SC_OK) return 1;
    cn_transfer_transition(&x, CN_XFR_SOURCE_VERIFIED, "fixture \"quoted\" detail");
    if (cn_store_upsert_transfer(st, &x) != SC_OK) return 1;
    char hex[65]; crypto_hex_encode(x.transfer_id, 32, hex);
    printf("%s\n", hex);
    cn_store_close(st);
    return 0;
}
