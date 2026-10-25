/* cn_store.c - Persistent store implementation for SovereignChain connector. */
#define _POSIX_C_SOURCE 200809L

#include "cn_store.h"
#include "cn_activity.h"
#include "cn_transfer.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define ACTIVITY_ENTRY_LEN (8 + CN_ACTIVITY_WIRE_LEN) /* 8 seq + 299 wire = 307 bytes */
#define TRANSFERS_FILE_MAGIC "CNXFER01"
#define TRANSFER_FULL_WIRE_LEN (CN_TRANSFER_CORE_WIRE_LEN + 4 + (CN_MAX_PEERS * 64) + (CN_MAX_PEERS * 32) + 32 + 1 + 256)

struct cn_store {
    char data_dir[CN_MAX_PATH];

    /* Activity records */
    FILE *act_file;
    cn_activity_record_t *activities;
    size_t activity_count;
    size_t activity_cap;

    /* Transfers */
    cn_transfer_t *transfers;
    size_t transfer_count;
    size_t transfer_cap;

    /* Seen IDs */
    FILE *seen_file;
    uint8_t (*seen_ids)[SC_SHA256_LEN];
    size_t seen_count;
    size_t seen_cap;
};

static void pack_u64_be(uint8_t *dest, uint64_t val)
{
    for (int i = 7; i >= 0; i--) {
        dest[i] = (uint8_t)(val & 0xFF);
        val >>= 8;
    }
}

static uint64_t unpack_u64_be(const uint8_t *src)
{
    uint64_t val = 0;
    for (int i = 0; i < 8; i++) {
        val = (val << 8) | src[i];
    }
    return val;
}

static void pack_u32_be(uint8_t *dest, uint32_t val)
{
    dest[0] = (uint8_t)((val >> 24) & 0xFF);
    dest[1] = (uint8_t)((val >> 16) & 0xFF);
    dest[2] = (uint8_t)((val >> 8) & 0xFF);
    dest[3] = (uint8_t)(val & 0xFF);
}

static uint32_t unpack_u32_be(const uint8_t *src)
{
    return ((uint32_t)src[0] << 24) |
           ((uint32_t)src[1] << 16) |
           ((uint32_t)src[2] << 8)  |
           (uint32_t)src[3];
}

static sc_err_t serialize_full_transfer(const cn_transfer_t *xfr, uint8_t *buf, size_t buflen)
{
    if (buflen < TRANSFER_FULL_WIRE_LEN)
        return SC_ERR_INVALID;

    size_t written = 0;
    if (cn_transfer_serialize(xfr, buf, buflen, &written) != SC_OK)
        return SC_ERR_INVALID;

    uint8_t *p = buf + CN_TRANSFER_CORE_WIRE_LEN;
    pack_u32_be(p, (uint32_t)xfr->cert_sig_count);
    p += 4;

    for (size_t i = 0; i < CN_MAX_PEERS; i++) {
        memcpy(p, xfr->cert_sigs[i], SC_ED25519_SIG_LEN);
        p += SC_ED25519_SIG_LEN;
    }

    for (size_t i = 0; i < CN_MAX_PEERS; i++) {
        memcpy(p, xfr->cert_signers[i], SC_ED25519_PUBKEY_LEN);
        p += SC_ED25519_PUBKEY_LEN;
    }

    memcpy(p, xfr->dest_tx_hash, SC_SHA256_LEN);
    p += SC_SHA256_LEN;

    *p = xfr->dest_tx_hash_valid ? 1 : 0;
    p += 1;

    memcpy(p, xfr->error_detail, 256);
    p += 256;

    return SC_OK;
}

static sc_err_t deserialize_full_transfer(cn_transfer_t *xfr, const uint8_t *buf, size_t len)
{
    if (len < TRANSFER_FULL_WIRE_LEN)
        return SC_ERR_INVALID;

    if (cn_transfer_deserialize(xfr, buf, len) != SC_OK)
        return SC_ERR_INVALID;

    const uint8_t *p = buf + CN_TRANSFER_CORE_WIRE_LEN;
    xfr->cert_sig_count = (size_t)unpack_u32_be(p);
    if (xfr->cert_sig_count > CN_MAX_PEERS)
        xfr->cert_sig_count = CN_MAX_PEERS;
    p += 4;

    for (size_t i = 0; i < CN_MAX_PEERS; i++) {
        memcpy(xfr->cert_sigs[i], p, SC_ED25519_SIG_LEN);
        p += SC_ED25519_SIG_LEN;
    }

    for (size_t i = 0; i < CN_MAX_PEERS; i++) {
        memcpy(xfr->cert_signers[i], p, SC_ED25519_PUBKEY_LEN);
        p += SC_ED25519_PUBKEY_LEN;
    }

    memcpy(xfr->dest_tx_hash, p, SC_SHA256_LEN);
    p += SC_SHA256_LEN;

    xfr->dest_tx_hash_valid = (*p != 0);
    p += 1;

    memcpy(xfr->error_detail, p, 256);
    xfr->error_detail[255] = '\0';

    return SC_OK;
}

static sc_err_t load_activities(cn_store_t *s)
{
    char path[CN_MAX_PATH + 64];
    snprintf(path, sizeof(path), "%s/activity.dat", s->data_dir);

    FILE *f = fopen(path, "rb");
    if (!f) {
        if (errno == ENOENT)
            return SC_OK;
        return SC_ERR_IO;
    }

    uint8_t buf[ACTIVITY_ENTRY_LEN];
    while (fread(buf, 1, sizeof(buf), f) == sizeof(buf)) {
        if (s->activity_count >= s->activity_cap) {
            size_t ncap = s->activity_cap ? s->activity_cap * 2 : 64;
            cn_activity_record_t *p = realloc(s->activities, ncap * sizeof(cn_activity_record_t));
            if (!p) {
                fclose(f);
                return SC_ERR_IO;
            }
            s->activities = p;
            s->activity_cap = ncap;
        }
        if (cn_activity_deserialize(&s->activities[s->activity_count], buf + 8, CN_ACTIVITY_WIRE_LEN) == SC_OK) {
            s->activity_count++;
        }
    }

    fclose(f);
    return SC_OK;
}

static sc_err_t load_transfers(cn_store_t *s)
{
    char path[CN_MAX_PATH + 64];
    snprintf(path, sizeof(path), "%s/transfers.dat", s->data_dir);

    FILE *f = fopen(path, "rb");
    if (!f) {
        if (errno == ENOENT)
            return SC_OK;
        return SC_ERR_IO;
    }

    uint8_t hdr[16];
    if (fread(hdr, 1, sizeof(hdr), f) != sizeof(hdr)) {
        fclose(f);
        return SC_OK;
    }

    if (memcmp(hdr, TRANSFERS_FILE_MAGIC, 8) != 0) {
        fclose(f);
        return SC_ERR_PARSE;
    }

    uint64_t count = unpack_u64_be(hdr + 8);
    uint8_t buf[TRANSFER_FULL_WIRE_LEN];

    for (uint64_t i = 0; i < count; i++) {
        if (fread(buf, 1, sizeof(buf), f) != sizeof(buf))
            break;
        if (s->transfer_count >= s->transfer_cap) {
            size_t ncap = s->transfer_cap ? s->transfer_cap * 2 : 16;
            cn_transfer_t *p = realloc(s->transfers, ncap * sizeof(cn_transfer_t));
            if (!p) {
                fclose(f);
                return SC_ERR_IO;
            }
            s->transfers = p;
            s->transfer_cap = ncap;
        }
        if (deserialize_full_transfer(&s->transfers[s->transfer_count], buf, sizeof(buf)) == SC_OK) {
            s->transfer_count++;
        }
    }

    fclose(f);
    return SC_OK;
}

static sc_err_t load_seen_ids(cn_store_t *s)
{
    char path[CN_MAX_PATH + 64];
    snprintf(path, sizeof(path), "%s/seen_ids.dat", s->data_dir);

    FILE *f = fopen(path, "rb");
    if (!f) {
        if (errno == ENOENT)
            return SC_OK;
        return SC_ERR_IO;
    }

    uint8_t id[SC_SHA256_LEN];
    while (fread(id, 1, sizeof(id), f) == sizeof(id)) {
        if (s->seen_count >= s->seen_cap) {
            size_t ncap = s->seen_cap ? s->seen_cap * 2 : 64;
            uint8_t (*p)[SC_SHA256_LEN] = realloc(s->seen_ids, ncap * sizeof(*p));
            if (!p) {
                fclose(f);
                return SC_ERR_IO;
            }
            s->seen_ids = p;
            s->seen_cap = ncap;
        }
        memcpy(s->seen_ids[s->seen_count], id, SC_SHA256_LEN);
        s->seen_count++;
    }

    fclose(f);
    return SC_OK;
}

sc_err_t cn_store_open(cn_store_t **store_out, const char *data_dir)
{
    if (!store_out || !data_dir)
        return SC_ERR_INVALID;

    /* Ensure data_dir exists */
    struct stat st;
    if (stat(data_dir, &st) != 0) {
        if (mkdir(data_dir, 0755) != 0 && errno != EEXIST) {
            return SC_ERR_IO;
        }
    }

    cn_store_t *s = calloc(1, sizeof(*s));
    if (!s)
        return SC_ERR_IO;

    snprintf(s->data_dir, sizeof(s->data_dir), "%s", data_dir);

    sc_err_t rc = load_activities(s);
    if (rc != SC_OK) {
        cn_store_close(s);
        return rc;
    }

    rc = load_transfers(s);
    if (rc != SC_OK) {
        cn_store_close(s);
        return rc;
    }

    rc = load_seen_ids(s);
    if (rc != SC_OK) {
        cn_store_close(s);
        return rc;
    }

    /* Open append-only files */
    char act_path[CN_MAX_PATH + 64];
    snprintf(act_path, sizeof(act_path), "%s/activity.dat", s->data_dir);
    s->act_file = fopen(act_path, "a+b");
    if (!s->act_file) {
        cn_store_close(s);
        return SC_ERR_IO;
    }

    char seen_path[CN_MAX_PATH + 64];
    snprintf(seen_path, sizeof(seen_path), "%s/seen_ids.dat", s->data_dir);
    s->seen_file = fopen(seen_path, "a+b");
    if (!s->seen_file) {
        cn_store_close(s);
        return SC_ERR_IO;
    }

    *store_out = s;
    return SC_OK;
}

void cn_store_close(cn_store_t *store)
{
    if (!store)
        return;

    if (store->act_file) {
        fflush(store->act_file);
        fclose(store->act_file);
        store->act_file = NULL;
    }

    if (store->seen_file) {
        fflush(store->seen_file);
        fclose(store->seen_file);
        store->seen_file = NULL;
    }

    free(store->activities);
    free(store->transfers);
    free(store->seen_ids);
    free(store);
}

sc_err_t cn_store_has_activity(cn_store_t *store, const uint8_t record_id[32], bool *out)
{
    if (!store || !record_id || !out)
        return SC_ERR_INVALID;

    *out = false;
    for (size_t i = 0; i < store->activity_count; i++) {
        if (memcmp(store->activities[i].record_id, record_id, SC_SHA256_LEN) == 0) {
            *out = true;
            return SC_OK;
        }
    }
    return SC_OK;
}

sc_err_t cn_store_add_activity(cn_store_t *store, const cn_activity_record_t *rec)
{
    if (!store || !rec)
        return SC_ERR_INVALID;

    bool exists = false;
    cn_store_has_activity(store, rec->record_id, &exists);
    if (exists)
        return SC_OK; /* Idempotent add */

    /* Append to disk */
    uint8_t entry[ACTIVITY_ENTRY_LEN];
    uint64_t seq = (uint64_t)(store->activity_count + 1);
    pack_u64_be(entry, seq);

    size_t written = 0;
    if (cn_activity_serialize(rec, entry + 8, CN_ACTIVITY_WIRE_LEN, &written) != SC_OK)
        return SC_ERR_INVALID;

    if (fwrite(entry, 1, sizeof(entry), store->act_file) != sizeof(entry))
        return SC_ERR_IO;

    fflush(store->act_file);
    int fd = fileno(store->act_file);
    if (fd >= 0)
        fsync(fd);

    /* Append to in-memory array */
    if (store->activity_count >= store->activity_cap) {
        size_t ncap = store->activity_cap ? store->activity_cap * 2 : 64;
        cn_activity_record_t *p = realloc(store->activities, ncap * sizeof(cn_activity_record_t));
        if (!p)
            return SC_ERR_IO;
        store->activities = p;
        store->activity_cap = ncap;
    }
    store->activities[store->activity_count++] = *rec;

    return SC_OK;
}

sc_err_t cn_store_get_activity_since(cn_store_t *store, uint64_t since_seq, 
                                      cn_activity_record_t *out, size_t max, size_t *count_out)
{
    if (!store || !out || !count_out)
        return SC_ERR_INVALID;

    size_t count = 0;
    for (size_t i = 0; i < store->activity_count && count < max; i++) {
        uint64_t seq = (uint64_t)(i + 1);
        if (seq > since_seq) {
            out[count++] = store->activities[i];
        }
    }

    *count_out = count;
    return SC_OK;
}

uint64_t cn_store_activity_count(cn_store_t *store)
{
    return store ? (uint64_t)store->activity_count : 0;
}

sc_err_t cn_store_get_activity_by_id(cn_store_t *store, const uint8_t record_id[32],
                                      cn_activity_record_t *out)
{
    if (!store || !record_id || !out)
        return SC_ERR_INVALID;

    for (size_t i = 0; i < store->activity_count; i++) {
        if (memcmp(store->activities[i].record_id, record_id, SC_SHA256_LEN) == 0) {
            *out = store->activities[i];
            return SC_OK;
        }
    }
    return SC_ERR_NOT_FOUND;
}

sc_err_t cn_store_has_transfer(cn_store_t *store, const uint8_t transfer_id[32], bool *out)
{
    if (!store || !transfer_id || !out)
        return SC_ERR_INVALID;

    *out = false;
    for (size_t i = 0; i < store->transfer_count; i++) {
        if (memcmp(store->transfers[i].transfer_id, transfer_id, SC_SHA256_LEN) == 0) {
            *out = true;
            return SC_OK;
        }
    }
    return SC_OK;
}

static sc_err_t save_transfers_atomic(cn_store_t *store)
{
    char tmp[CN_MAX_PATH + 64];
    char target[CN_MAX_PATH + 64];
    snprintf(tmp, sizeof(tmp), "%s/transfers.dat.tmp", store->data_dir);
    snprintf(target, sizeof(target), "%s/transfers.dat", store->data_dir);

    FILE *f = fopen(tmp, "wb");
    if (!f)
        return SC_ERR_IO;

    uint8_t hdr[16];
    memset(hdr, 0, sizeof(hdr));
    memcpy(hdr, TRANSFERS_FILE_MAGIC, 8);
    pack_u64_be(hdr + 8, (uint64_t)store->transfer_count);

    if (fwrite(hdr, 1, sizeof(hdr), f) != sizeof(hdr)) {
        fclose(f);
        unlink(tmp);
        return SC_ERR_IO;
    }

    uint8_t buf[TRANSFER_FULL_WIRE_LEN];
    for (size_t i = 0; i < store->transfer_count; i++) {
        if (serialize_full_transfer(&store->transfers[i], buf, sizeof(buf)) != SC_OK) {
            fclose(f);
            unlink(tmp);
            return SC_ERR_INVALID;
        }
        if (fwrite(buf, 1, sizeof(buf), f) != sizeof(buf)) {
            fclose(f);
            unlink(tmp);
            return SC_ERR_IO;
        }
    }

    fflush(f);
    int fd = fileno(f);
    if (fd >= 0)
        fsync(fd);
    fclose(f);

    if (rename(tmp, target) != 0) {
        unlink(tmp);
        return SC_ERR_IO;
    }

    return SC_OK;
}

sc_err_t cn_store_upsert_transfer(cn_store_t *store, const cn_transfer_t *xfr)
{
    if (!store || !xfr)
        return SC_ERR_INVALID;

    ssize_t found_idx = -1;
    for (size_t i = 0; i < store->transfer_count; i++) {
        if (memcmp(store->transfers[i].transfer_id, xfr->transfer_id, SC_SHA256_LEN) == 0) {
            found_idx = (ssize_t)i;
            break;
        }
    }

    if (found_idx >= 0) {
        store->transfers[found_idx] = *xfr;
    } else {
        if (store->transfer_count >= store->transfer_cap) {
            size_t ncap = store->transfer_cap ? store->transfer_cap * 2 : 16;
            cn_transfer_t *p = realloc(store->transfers, ncap * sizeof(cn_transfer_t));
            if (!p)
                return SC_ERR_IO;
            store->transfers = p;
            store->transfer_cap = ncap;
        }
        store->transfers[store->transfer_count++] = *xfr;
    }

    return save_transfers_atomic(store);
}

sc_err_t cn_store_get_transfer(cn_store_t *store, const uint8_t transfer_id[32],
                                cn_transfer_t *out)
{
    if (!store || !transfer_id || !out)
        return SC_ERR_INVALID;

    for (size_t i = 0; i < store->transfer_count; i++) {
        if (memcmp(store->transfers[i].transfer_id, transfer_id, SC_SHA256_LEN) == 0) {
            *out = store->transfers[i];
            return SC_OK;
        }
    }
    return SC_ERR_NOT_FOUND;
}

sc_err_t cn_store_get_transfers_by_state(cn_store_t *store, cn_transfer_state_t state,
                                          cn_transfer_t *out, size_t max, size_t *count_out)
{
    if (!store || !out || !count_out)
        return SC_ERR_INVALID;

    size_t count = 0;
    for (size_t i = 0; i < store->transfer_count && count < max; i++) {
        if (store->transfers[i].state == (uint8_t)state) {
            out[count++] = store->transfers[i];
        }
    }

    *count_out = count;
    return SC_OK;
}

size_t cn_store_transfer_count(cn_store_t *store)
{
    return store ? store->transfer_count : 0;
}

sc_err_t cn_store_get_transfer_at(cn_store_t *store, size_t index, cn_transfer_t *out)
{
    if (!store || !out)
        return SC_ERR_INVALID;
    if (index >= store->transfer_count)
        return SC_ERR_NOT_FOUND;
    *out = store->transfers[index];
    return SC_OK;
}

sc_err_t cn_store_is_seen(cn_store_t *store, const uint8_t id[32], bool *out)
{
    if (!store || !id || !out)
        return SC_ERR_INVALID;

    *out = false;
    for (size_t i = 0; i < store->seen_count; i++) {
        if (memcmp(store->seen_ids[i], id, SC_SHA256_LEN) == 0) {
            *out = true;
            return SC_OK;
        }
    }
    return SC_OK;
}

sc_err_t cn_store_mark_seen(cn_store_t *store, const uint8_t id[32])
{
    if (!store || !id)
        return SC_ERR_INVALID;

    bool seen = false;
    cn_store_is_seen(store, id, &seen);
    if (seen)
        return SC_OK;

    if (fwrite(id, 1, SC_SHA256_LEN, store->seen_file) != SC_SHA256_LEN)
        return SC_ERR_IO;

    fflush(store->seen_file);
    int fd = fileno(store->seen_file);
    if (fd >= 0)
        fsync(fd);

    if (store->seen_count >= store->seen_cap) {
        size_t ncap = store->seen_cap ? store->seen_cap * 2 : 64;
        uint8_t (*p)[SC_SHA256_LEN] = realloc(store->seen_ids, ncap * sizeof(*p));
        if (!p)
            return SC_ERR_IO;
        store->seen_ids = p;
        store->seen_cap = ncap;
    }
    memcpy(store->seen_ids[store->seen_count++], id, SC_SHA256_LEN);

    return SC_OK;
}
