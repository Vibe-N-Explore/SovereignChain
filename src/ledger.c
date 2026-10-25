/* ledger.c - SovereignChain state engine implementation. */
#define _POSIX_C_SOURCE 200809L

#include "ledger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto.h"
#include "log.h"

struct sc_ledger {
    sc_account_t accounts[SC_MAX_ACCOUNTS];
    size_t       account_count;

    uint8_t      executed_transfers[SC_MAX_EXECUTED_TRANSFERS][SC_TRANSFER_ID_LEN];
    size_t       executed_transfer_count;
};

sc_err_t ledger_create(sc_ledger_t **ledger_out)
{
    if (!ledger_out)
        return SC_ERR_INVALID;

    sc_ledger_t *l = calloc(1, sizeof(*l));
    if (!l)
        return SC_ERR_IO;

    *ledger_out = l;
    return SC_OK;
}

void ledger_free(sc_ledger_t *ledger)
{
    free(ledger);
}

void ledger_clear(sc_ledger_t *ledger)
{
    if (!ledger)
        return;
    memset(ledger->accounts, 0, sizeof(ledger->accounts));
    ledger->account_count = 0;
    ledger->executed_transfer_count = 0;
}

static sc_account_t *find_account(sc_ledger_t *l, const uint8_t pubkey[SC_ED25519_PUBKEY_LEN])
{
    for (size_t i = 0; i < l->account_count; i++) {
        if (l->accounts[i].active &&
            memcmp(l->accounts[i].pubkey, pubkey, SC_ED25519_PUBKEY_LEN) == 0) {
            return &l->accounts[i];
        }
    }
    return NULL;
}

sc_err_t ledger_get_account(const sc_ledger_t *ledger,
                           const uint8_t pubkey[SC_ED25519_PUBKEY_LEN],
                           sc_account_t *account_out)
{
    if (!ledger || !pubkey || !account_out)
        return SC_ERR_INVALID;

    for (size_t i = 0; i < ledger->account_count; i++) {
        if (ledger->accounts[i].active &&
            memcmp(ledger->accounts[i].pubkey, pubkey, SC_ED25519_PUBKEY_LEN) == 0) {
            *account_out = ledger->accounts[i];
            return SC_OK;
        }
    }
    return SC_ERR_NOT_FOUND;
}

sc_err_t ledger_set_account(sc_ledger_t *ledger,
                           const uint8_t pubkey[SC_ED25519_PUBKEY_LEN],
                           uint64_t balance,
                           uint64_t nonce)
{
    if (!ledger || !pubkey)
        return SC_ERR_INVALID;

    sc_account_t *acc = find_account(ledger, pubkey);
    if (acc) {
        acc->balance = balance;
        acc->nonce = nonce;
        return SC_OK;
    }

    if (ledger->account_count >= SC_MAX_ACCOUNTS)
        return SC_ERR_IO;

    acc = &ledger->accounts[ledger->account_count++];
    memcpy(acc->pubkey, pubkey, SC_ED25519_PUBKEY_LEN);
    acc->balance = balance;
    acc->nonce = nonce;
    acc->active = true;

    return SC_OK;
}

bool ledger_has_executed_transfer(const sc_ledger_t *ledger, const uint8_t transfer_id[SC_TRANSFER_ID_LEN])
{
    if (!ledger || !transfer_id)
        return false;

    for (size_t i = 0; i < ledger->executed_transfer_count; i++) {
        if (memcmp(ledger->executed_transfers[i], transfer_id, SC_TRANSFER_ID_LEN) == 0) {
            return true;
        }
    }
    return false;
}

sc_err_t ledger_record_executed_transfer(sc_ledger_t *ledger, const uint8_t transfer_id[SC_TRANSFER_ID_LEN])
{
    if (!ledger || !transfer_id)
        return SC_ERR_INVALID;

    if (ledger_has_executed_transfer(ledger, transfer_id))
        return SC_OK;

    if (ledger->executed_transfer_count >= SC_MAX_EXECUTED_TRANSFERS)
        return SC_ERR_IO;

    memcpy(ledger->executed_transfers[ledger->executed_transfer_count++],
           transfer_id, SC_TRANSFER_ID_LEN);
    return SC_OK;
}

sc_err_t ledger_apply_tx(sc_ledger_t *ledger, const sc_tx_t *tx)
{
    if (!ledger || !tx)
        return SC_ERR_INVALID;

    if (tx_verify_sig(tx) != SC_OK) {
        log_event(LOG_WARN, "ledger", "apply_tx_invalid_sig");
        return SC_ERR_INVALID;
    }

    sc_account_t *sender = find_account(ledger, tx->sender);
    if (!sender) {
        log_event(LOG_WARN, "ledger", "apply_tx_sender_not_found");
        return SC_ERR_NOT_FOUND;
    }

    if (tx->nonce != sender->nonce) {
        log_eventf(LOG_WARN, "ledger", "apply_tx_bad_nonce",
                   "expected=%llu got=%llu",
                   (unsigned long long)sender->nonce,
                   (unsigned long long)tx->nonce);
        return SC_ERR_INVALID;
    }

    uint64_t total = tx->amount + tx->fee;
    if (sender->balance < total) {
        log_eventf(LOG_WARN, "ledger", "apply_tx_insufficient_funds",
                   "bal=%llu required=%llu",
                   (unsigned long long)sender->balance,
                   (unsigned long long)total);
        return SC_ERR_INVALID;
    }

    sender->balance -= total;
    sender->nonce++;

    sc_account_t *recipient = find_account(ledger, tx->recipient);
    if (!recipient) {
        if (ledger->account_count >= SC_MAX_ACCOUNTS) {
            sender->balance += total;
            sender->nonce--;
            return SC_ERR_IO;
        }
        recipient = &ledger->accounts[ledger->account_count++];
        memcpy(recipient->pubkey, tx->recipient, SC_ED25519_PUBKEY_LEN);
        recipient->balance = 0;
        recipient->nonce = 0;
        recipient->active = true;
    }

    recipient->balance += tx->amount;

    return SC_OK;
}

sc_err_t ledger_apply_block(sc_ledger_t *ledger,
                            const sc_tx_t *txs,
                            size_t count,
                            bool stop_on_failure,
                            size_t *applied_count_out)
{
    if (applied_count_out)
        *applied_count_out = 0;

    if (!ledger || (!txs && count > 0))
        return SC_ERR_INVALID;

    size_t applied = 0;
    for (size_t i = 0; i < count; i++) {
        sc_err_t rc = ledger_apply_tx(ledger, &txs[i]);
        if (rc == SC_OK) {
            applied++;
        } else if (stop_on_failure) {
            if (applied_count_out)
                *applied_count_out = applied;
            return rc;
        }
    }

    if (applied_count_out)
        *applied_count_out = applied;

    return SC_OK;
}

static int compare_accounts_by_pubkey(const void *a, const void *b)
{
    const sc_account_t *acc1 = (const sc_account_t *)a;
    const sc_account_t *acc2 = (const sc_account_t *)b;
    return memcmp(acc1->pubkey, acc2->pubkey, SC_ED25519_PUBKEY_LEN);
}

sc_err_t ledger_compute_state_hash(const sc_ledger_t *ledger,
                                   uint8_t hash_out[SC_SHA256_LEN])
{
    if (!ledger || !hash_out)
        return SC_ERR_INVALID;

    sc_account_t active[SC_MAX_ACCOUNTS];
    size_t count = 0;

    for (size_t i = 0; i < ledger->account_count; i++) {
        if (ledger->accounts[i].active) {
            active[count++] = ledger->accounts[i];
        }
    }

    qsort(active, count, sizeof(sc_account_t), compare_accounts_by_pubkey);

    size_t buf_size = count * 48;
    uint8_t *buf = malloc(buf_size > 0 ? buf_size : 1);
    if (!buf)
        return SC_ERR_IO;

    for (size_t i = 0; i < count; i++) {
        uint8_t *p = buf + (i * 48);
        memcpy(p, active[i].pubkey, SC_ED25519_PUBKEY_LEN);

        p[32] = (uint8_t)(active[i].balance >> 56);
        p[33] = (uint8_t)(active[i].balance >> 48);
        p[34] = (uint8_t)(active[i].balance >> 40);
        p[35] = (uint8_t)(active[i].balance >> 32);
        p[36] = (uint8_t)(active[i].balance >> 24);
        p[37] = (uint8_t)(active[i].balance >> 16);
        p[38] = (uint8_t)(active[i].balance >> 8);
        p[39] = (uint8_t)(active[i].balance);

        p[40] = (uint8_t)(active[i].nonce >> 56);
        p[41] = (uint8_t)(active[i].nonce >> 48);
        p[42] = (uint8_t)(active[i].nonce >> 40);
        p[43] = (uint8_t)(active[i].nonce >> 32);
        p[44] = (uint8_t)(active[i].nonce >> 24);
        p[45] = (uint8_t)(active[i].nonce >> 16);
        p[46] = (uint8_t)(active[i].nonce >> 8);
        p[47] = (uint8_t)(active[i].nonce);
    }

    crypto_sha256(buf, buf_size, hash_out);
    free(buf);

    return SC_OK;
}

const sc_account_t *ledger_get_accounts_raw(const sc_ledger_t *ledger, size_t *count_out)
{
    if (!ledger || !count_out)
        return NULL;
    *count_out = ledger->account_count;
    return ledger->accounts;
}