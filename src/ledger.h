/* ledger.h - SovereignChain account ledger and state root engine. */
#ifndef SC_LEDGER_H
#define SC_LEDGER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "crypto.h"
#include "err.h"
#include "tx.h"

#define SC_MAX_ACCOUNTS 1024
#define SC_MAX_EXECUTED_TRANSFERS 4096
#define SC_TRANSFER_ID_LEN 32

typedef struct {
    uint8_t  pubkey[SC_ED25519_PUBKEY_LEN];
    uint64_t balance;
    uint64_t nonce;
    bool     active;
} sc_account_t;

typedef struct sc_ledger sc_ledger_t;

sc_err_t ledger_create(sc_ledger_t **ledger_out);
void ledger_free(sc_ledger_t *ledger);
void ledger_clear(sc_ledger_t *ledger);

sc_err_t ledger_get_account(const sc_ledger_t *ledger,
                           const uint8_t pubkey[SC_ED25519_PUBKEY_LEN],
                           sc_account_t *account_out);

sc_err_t ledger_set_account(sc_ledger_t *ledger,
                           const uint8_t pubkey[SC_ED25519_PUBKEY_LEN],
                           uint64_t balance,
                           uint64_t nonce);

sc_err_t ledger_apply_tx(sc_ledger_t *ledger, const sc_tx_t *tx);

sc_err_t ledger_apply_block(sc_ledger_t *ledger,
                            const sc_tx_t *txs,
                            size_t count,
                            bool stop_on_failure,
                            size_t *applied_count_out);

sc_err_t ledger_compute_state_hash(const sc_ledger_t *ledger,
                                   uint8_t hash_out[SC_SHA256_LEN]);

bool ledger_has_executed_transfer(const sc_ledger_t *ledger, const uint8_t transfer_id[SC_TRANSFER_ID_LEN]);
sc_err_t ledger_record_executed_transfer(sc_ledger_t *ledger, const uint8_t transfer_id[SC_TRANSFER_ID_LEN]);

const sc_account_t *ledger_get_accounts_raw(const sc_ledger_t *ledger, size_t *count_out);

#endif /* SC_LEDGER_H */