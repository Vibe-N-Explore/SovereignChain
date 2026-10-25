/* storage.c - Persistence and crash-recovery for SovereignChain ledger. */
#define _POSIX_C_SOURCE 200809L

#include "storage.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "crypto.h"
#include "log.h"

static void set_err(char *errbuf, size_t errlen, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

static void set_err(char *errbuf, size_t errlen, const char *fmt, ...)
{
    if (!errbuf || errlen == 0)
        return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(errbuf, errlen, fmt, ap);
    va_end(ap);
}

static void pack_u64_be(uint8_t *dest, uint64_t val)
{
    dest[0] = (uint8_t)(val >> 56);
    dest[1] = (uint8_t)(val >> 48);
    dest[2] = (uint8_t)(val >> 40);
    dest[3] = (uint8_t)(val >> 32);
    dest[4] = (uint8_t)(val >> 24);
    dest[5] = (uint8_t)(val >> 16);
    dest[6] = (uint8_t)(val >> 8);
    dest[7] = (uint8_t)(val);
}

static uint64_t unpack_u64_be(const uint8_t *src)
{
    return ((uint64_t)src[0] << 56) |
           ((uint64_t)src[1] << 48) |
           ((uint64_t)src[2] << 40) |
           ((uint64_t)src[3] << 32) |
           ((uint64_t)src[4] << 24) |
           ((uint64_t)src[5] << 16) |
           ((uint64_t)src[6] << 8)  |
           ((uint64_t)src[7]);
}

bool storage_state_exists(const char *data_dir)
{
    if (!data_dir)
        return false;
    char path[512];
    snprintf(path, sizeof(path), "%s/state.dat", data_dir);
    return (access(path, F_OK) == 0);
}

sc_err_t storage_save_state(const sc_ledger_t *ledger, const char *data_dir,
                            char *errbuf, size_t errlen)
{
    if (!ledger || !data_dir) {
        set_err(errbuf, errlen, "invalid_arguments");
        return SC_ERR_INVALID;
    }

    mkdir(data_dir, 0755);

    char tmp_path[512];
    char final_path[512];
    snprintf(tmp_path, sizeof(tmp_path), "%s/state.dat.tmp", data_dir);
    snprintf(final_path, sizeof(final_path), "%s/state.dat", data_dir);

    FILE *f = fopen(tmp_path, "wb");
    if (!f) {
        set_err(errbuf, errlen, "cannot_open_tmp_file: %s", strerror(errno));
        return SC_ERR_IO;
    }

    size_t count = 0;
    const sc_account_t *accounts = ledger_get_accounts_raw(ledger, &count);

    uint8_t state_hash[SC_SHA256_LEN];
    if (ledger_compute_state_hash(ledger, state_hash) != SC_OK) {
        set_err(errbuf, errlen, "state_hash_calculation_failed");
        fclose(f);
        unlink(tmp_path);
        return SC_ERR_IO;
    }

    /* 1. Header */
    uint8_t header[4 + 4 + 8 + SC_SHA256_LEN];
    pack_u64_be(header, ((uint64_t)SC_STORAGE_MAGIC << 32) | SC_STORAGE_VERSION);
    pack_u64_be(header + 8, (uint64_t)count);
    memcpy(header + 16, state_hash, SC_SHA256_LEN);

    if (fwrite(header, 1, sizeof(header), f) != sizeof(header)) {
        set_err(errbuf, errlen, "write_header_failed: %s", strerror(errno));
        fclose(f);
        unlink(tmp_path);
        return SC_ERR_IO;
    }

    /* 2. Account records */
    for (size_t i = 0; i < count; i++) {
        uint8_t record[SC_ED25519_PUBKEY_LEN + 8 + 8];
        memcpy(record, accounts[i].pubkey, SC_ED25519_PUBKEY_LEN);
        pack_u64_be(record + 32, accounts[i].balance);
        pack_u64_be(record + 40, accounts[i].nonce);

        if (fwrite(record, 1, sizeof(record), f) != sizeof(record)) {
            set_err(errbuf, errlen, "write_record_failed: %s", strerror(errno));
            fclose(f);
            unlink(tmp_path);
            return SC_ERR_IO;
        }
    }

    fflush(f);
    int fd = fileno(f);
    if (fd >= 0)
        fsync(fd);
    fclose(f);

    /* Atomic rename replaces target state.dat */
    if (rename(tmp_path, final_path) != 0) {
        set_err(errbuf, errlen, "rename_failed: %s", strerror(errno));
        unlink(tmp_path);
        return SC_ERR_IO;
    }

    return SC_OK;
}

sc_err_t storage_load_state(sc_ledger_t *ledger, const char *data_dir,
                            char *errbuf, size_t errlen)
{
    if (!ledger || !data_dir) {
        set_err(errbuf, errlen, "invalid_arguments");
        return SC_ERR_INVALID;
    }

    char path[512];
    snprintf(path, sizeof(path), "%s/state.dat", data_dir);

    FILE *f = fopen(path, "rb");
    if (!f) {
        set_err(errbuf, errlen, "cannot_open_state_file: %s", strerror(errno));
        return SC_ERR_NOT_FOUND;
    }

    /* 1. Read header */
    uint8_t header[4 + 4 + 8 + SC_SHA256_LEN];
    if (fread(header, 1, sizeof(header), f) != sizeof(header)) {
        set_err(errbuf, errlen, "corrupt_header_eof");
        fclose(f);
        return SC_ERR_PARSE;
    }

    uint64_t magic_ver = unpack_u64_be(header);
    uint32_t magic = (uint32_t)(magic_ver >> 32);
    uint32_t version = (uint32_t)(magic_ver & 0xFFFFFFFF);

    if (magic != SC_STORAGE_MAGIC) {
        set_err(errbuf, errlen, "invalid_magic_header");
        fclose(f);
        return SC_ERR_INVALID;
    }
    if (version != SC_STORAGE_VERSION) {
        set_err(errbuf, errlen, "unsupported_storage_version: %u", version);
        fclose(f);
        return SC_ERR_INVALID;
    }

    uint64_t count = unpack_u64_be(header + 8);
    uint8_t expected_state_hash[SC_SHA256_LEN];
    memcpy(expected_state_hash, header + 16, SC_SHA256_LEN);

    /* Reset current ledger */
    ledger_clear(ledger);

    /* 2. Read records */
    for (uint64_t i = 0; i < count; i++) {
        uint8_t record[SC_ED25519_PUBKEY_LEN + 8 + 8];
        if (fread(record, 1, sizeof(record), f) != sizeof(record)) {
            set_err(errbuf, errlen, "truncated_account_record_at_index_%llu", (unsigned long long)i);
            fclose(f);
            return SC_ERR_PARSE;
        }

        uint64_t balance = unpack_u64_be(record + 32);
        uint64_t nonce   = unpack_u64_be(record + 40);

        sc_err_t rc = ledger_set_account(ledger, record, balance, nonce);
        if (rc != SC_OK) {
            set_err(errbuf, errlen, "ledger_set_account_failed");
            fclose(f);
            return rc;
        }
    }
    fclose(f);

    /* 3. Checksum verification: computed state root hash MUST match persisted hash */
    uint8_t actual_hash[SC_SHA256_LEN];
    if (ledger_compute_state_hash(ledger, actual_hash) != SC_OK) {
        set_err(errbuf, errlen, "state_hash_computation_failed");
        return SC_ERR_IO;
    }

    if (memcmp(actual_hash, expected_state_hash, SC_SHA256_LEN) != 0) {
        set_err(errbuf, errlen, "corrupt_state_checksum_mismatch");
        return SC_ERR_INVALID;
    }

    return SC_OK;
}
