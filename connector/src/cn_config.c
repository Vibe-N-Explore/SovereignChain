/* cn_config.c - Connector configuration parsing and rate persistence. */
#define _POSIX_C_SOURCE 200809L

#include "cn_config.h"

#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "../../src/crypto.h"
#include "../../src/config.h"
#include "../../src/err.h"

#define MAX_LINE_LEN 512
#define RATES_FILE_MAGIC "CNRATE01"

static void set_err(char *errbuf, size_t errlen, const char *fmt, ...)
{
    va_list ap;
    if (!errbuf || errlen == 0)
        return;
    va_start(ap, fmt);
    vsnprintf(errbuf, errlen, fmt, ap);
    va_end(ap);
}

static char *trim(char *s)
{
    char *end;
    while (*s == ' ' || *s == '\t')
        s++;
    end = s + strlen(s);
    while (end > s && (end[-1] == ' ' || end[-1] == '\t' ||
                       end[-1] == '\n' || end[-1] == '\r'))
        end--;
    *end = '\0';
    return s;
}

static bool parse_long(const char *s, long min, long max, long *out)
{
    char *end = NULL;
    long v;
    if (!s || *s == '\0')
        return false;
    errno = 0;
    v = strtol(s, &end, 10);
    if (errno != 0 || *end != '\0' || v < min || v > max)
        return false;
    *out = v;
    return true;
}

static bool parse_u64(const char *s, uint64_t *out)
{
    char *end = NULL;
    unsigned long long v;
    if (!s || *s == '\0')
        return false;
    errno = 0;
    v = strtoull(s, &end, 10);
    if (errno != 0 || *end != '\0')
        return false;
    *out = (uint64_t)v;
    return true;
}

static bool copy_str(char *dst, size_t cap, const char *src)
{
    size_t n = strlen(src);
    if (n == 0 || n >= cap)
        return false;
    memcpy(dst, src, n + 1);
    return true;
}

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

static void pack_i64_be(uint8_t *dest, int64_t val)
{
    pack_u64_be(dest, (uint64_t)val);
}

static int64_t unpack_i64_be(const uint8_t *src)
{
    return (int64_t)unpack_u64_be(src);
}

static void serialize_rate_wire(const cn_rate_t *r, uint8_t *out)
{
    pack_u64_be(out, r->rate_num);
    pack_u64_be(out + 8, r->rate_den);
    pack_u64_be(out + 16, r->version);
    pack_i64_be(out + 24, r->updated_at);
    memcpy(out + 32, r->updater_pubkey, SC_ED25519_PUBKEY_LEN);
    memcpy(out + 64, r->updater_sig, SC_ED25519_SIG_LEN);
}

static void deserialize_rate_wire(cn_rate_t *r, const uint8_t *in)
{
    r->rate_num = unpack_u64_be(in);
    r->rate_den = unpack_u64_be(in + 8);
    r->version = unpack_u64_be(in + 16);
    r->updated_at = unpack_i64_be(in + 24);
    memcpy(r->updater_pubkey, in + 32, SC_ED25519_PUBKEY_LEN);
    memcpy(r->updater_sig, in + 64, SC_ED25519_SIG_LEN);
}

sc_err_t cn_config_load(const char *path, cn_config_t *out,
                         char *errbuf, size_t errlen)
{
    if (!path || !out) {
        set_err(errbuf, errlen, "null argument");
        return SC_ERR_INVALID;
    }
    memset(out, 0, sizeof(*out));
    out->connector_id = -1;
    out->chain_a.chain_id = CN_CHAIN_A;
    out->chain_b.chain_id = CN_CHAIN_B;
    out->chain_a.our_node_id = -1;
    out->chain_b.our_node_id = -1;
    out->rate_a_to_b.rate_num = 1;
    out->rate_a_to_b.rate_den = 1;
    out->rate_a_to_b.version  = 1;
    out->rate_b_to_a.rate_num = 1;
    out->rate_b_to_a.rate_den = 1;
    out->rate_b_to_a.version  = 1;
    out->quorum = 1;
    out->log_level = 1; /* info */

    FILE *f = fopen(path, "r");
    if (!f) {
        set_err(errbuf, errlen, "cannot open %s: %s", path, strerror(errno));
        return SC_ERR_IO;
    }

    char raw[MAX_LINE_LEN];
    int lineno = 0;

    while (fgets(raw, sizeof(raw), f)) {
        lineno++;
        char *line = raw;
        char *hash = strchr(line, '#');
        if (hash)
            *hash = '\0';
        line = trim(line);
        if (*line == '\0')
            continue;

        /* Peer definition: peer <id> <host> <port> [<pubkey_hex>] */
        if (strncmp(line, "peer", 4) == 0 && (line[4] == ' ' || line[4] == '\t')) {
            if (out->peer_count >= CN_MAX_PEERS) {
                set_err(errbuf, errlen, "%s:%d: maximum peers (%d) exceeded",
                        path, lineno, CN_MAX_PEERS);
                fclose(f);
                return SC_ERR_INVALID;
            }
            char tok[4][68]; /* must hold a 64-char pubkey hex + NUL (was CN_MAX_HOST = 64) */
            memset(tok, 0, sizeof(tok));
            int parsed = sscanf(line + 4, "%67s %67s %67s %67s",
                                tok[0], tok[1], tok[2], tok[3]);
            if (parsed < 3) {
                set_err(errbuf, errlen, "%s:%d: invalid peer line syntax", path, lineno);
                fclose(f);
                return SC_ERR_PARSE;
            }
            long pid = 0;
            if (!parse_long(tok[0], 0, CN_MAX_PEERS - 1, &pid)) {
                set_err(errbuf, errlen, "%s:%d: invalid peer id: %s", path, lineno, tok[0]);
                fclose(f);
                return SC_ERR_PARSE;
            }
            long pport = 0;
            if (!parse_long(tok[2], 1, 65535, &pport)) {
                set_err(errbuf, errlen, "%s:%d: invalid peer port: %s", path, lineno, tok[2]);
                fclose(f);
                return SC_ERR_PARSE;
            }
            cn_peer_info_t *peer = &out->peers[out->peer_count++];
            peer->id = (int)pid;
            copy_str(peer->host, sizeof(peer->host), tok[1]);
            peer->port = (uint16_t)pport;
            peer->has_pubkey = false;

            if (parsed >= 4) {
                if (strlen(tok[3]) == 64 &&
                    crypto_hex_decode(tok[3], peer->pubkey, SC_ED25519_PUBKEY_LEN)) {
                    peer->has_pubkey = true;
                } else {
                    set_err(errbuf, errlen, "%s:%d: invalid peer pubkey hex", path, lineno);
                    fclose(f);
                    return SC_ERR_PARSE;
                }
            }
            continue;
        }

        /* Key = value parsing */
        char *eq = strchr(line, '=');
        if (!eq) {
            set_err(errbuf, errlen, "%s:%d: missing '=' in configuration line", path, lineno);
            fclose(f);
            return SC_ERR_PARSE;
        }
        *eq = '\0';
        char *key = trim(line);
        char *val = trim(eq + 1);

        if (strcmp(key, "connector_id") == 0) {
            long v;
            if (!parse_long(val, 0, CN_MAX_PEERS - 1, &v)) {
                set_err(errbuf, errlen, "%s:%d: invalid connector_id", path, lineno);
                fclose(f);
                return SC_ERR_PARSE;
            }
            out->connector_id = (int)v;
        } else if (strcmp(key, "key_path") == 0) {
            if (!copy_str(out->key_path, sizeof(out->key_path), val)) {
                set_err(errbuf, errlen, "%s:%d: key_path too long", path, lineno);
                fclose(f);
                return SC_ERR_PARSE;
            }
        } else if (strcmp(key, "data_dir") == 0) {
            if (!copy_str(out->data_dir, sizeof(out->data_dir), val)) {
                set_err(errbuf, errlen, "%s:%d: data_dir too long", path, lineno);
                fclose(f);
                return SC_ERR_PARSE;
            }
        } else if (strcmp(key, "listen_host") == 0) {
            if (!copy_str(out->listen_host, sizeof(out->listen_host), val)) {
                set_err(errbuf, errlen, "%s:%d: listen_host too long", path, lineno);
                fclose(f);
                return SC_ERR_PARSE;
            }
        } else if (strcmp(key, "listen_port") == 0) {
            long v;
            if (!parse_long(val, 1, 65535, &v)) {
                set_err(errbuf, errlen, "%s:%d: invalid listen_port", path, lineno);
                fclose(f);
                return SC_ERR_PARSE;
            }
            out->listen_port = (uint16_t)v;
        } else if (strcmp(key, "quorum") == 0) {
            long v;
            if (!parse_long(val, 1, CN_MAX_PEERS, &v)) {
                set_err(errbuf, errlen, "%s:%d: invalid quorum", path, lineno);
                fclose(f);
                return SC_ERR_PARSE;
            }
            out->quorum = (int)v;
        } else if (strcmp(key, "log_level") == 0) {
            long v;
            if (!parse_long(val, 0, 3, &v)) {
                set_err(errbuf, errlen, "%s:%d: invalid log_level", path, lineno);
                fclose(f);
                return SC_ERR_PARSE;
            }
            out->log_level = (int)v;
        } else if (strcmp(key, "chain_a_host") == 0) {
            copy_str(out->chain_a.host, sizeof(out->chain_a.host), val);
        } else if (strcmp(key, "chain_a_port") == 0) {
            long v;
            if (!parse_long(val, 1, 65535, &v)) {
                set_err(errbuf, errlen, "%s:%d: invalid chain_a_port", path, lineno);
                fclose(f);
                return SC_ERR_PARSE;
            }
            out->chain_a.port = (uint16_t)v;
        } else if (strcmp(key, "chain_a_pubkey") == 0) {
            if (strlen(val) == 64 && crypto_hex_decode(val, out->chain_a.pubkey, SC_ED25519_PUBKEY_LEN)) {
                out->chain_a.has_pubkey = true;
            } else {
                set_err(errbuf, errlen, "%s:%d: invalid chain_a_pubkey hex", path, lineno);
                fclose(f);
                return SC_ERR_PARSE;
            }
        } else if (strcmp(key, "chain_a_node_id") == 0) {
            long v;
            if (!parse_long(val, 0, SC_MAX_NODES - 1, &v)) {
                set_err(errbuf, errlen, "%s:%d: invalid chain_a_node_id", path, lineno);
                fclose(f);
                return SC_ERR_PARSE;
            }
            out->chain_a.our_node_id = (int)v;
        } else if (strcmp(key, "chain_a_bridge_pubkey") == 0) {
            if (strlen(val) == 64 && crypto_hex_decode(val, out->chain_a.bridge_pubkey, SC_ED25519_PUBKEY_LEN)) {
                out->chain_a.has_bridge_pubkey = true;
            } else {
                set_err(errbuf, errlen, "%s:%d: invalid chain_a_bridge_pubkey hex", path, lineno);
                fclose(f);
                return SC_ERR_PARSE;
            }
        } else if (strcmp(key, "chain_b_host") == 0) {
            copy_str(out->chain_b.host, sizeof(out->chain_b.host), val);
        } else if (strcmp(key, "chain_b_port") == 0) {
            long v;
            if (!parse_long(val, 1, 65535, &v)) {
                set_err(errbuf, errlen, "%s:%d: invalid chain_b_port", path, lineno);
                fclose(f);
                return SC_ERR_PARSE;
            }
            out->chain_b.port = (uint16_t)v;
        } else if (strcmp(key, "chain_b_pubkey") == 0) {
            if (strlen(val) == 64 && crypto_hex_decode(val, out->chain_b.pubkey, SC_ED25519_PUBKEY_LEN)) {
                out->chain_b.has_pubkey = true;
            } else {
                set_err(errbuf, errlen, "%s:%d: invalid chain_b_pubkey hex", path, lineno);
                fclose(f);
                return SC_ERR_PARSE;
            }
        } else if (strcmp(key, "chain_b_node_id") == 0) {
            long v;
            if (!parse_long(val, 0, SC_MAX_NODES - 1, &v)) {
                set_err(errbuf, errlen, "%s:%d: invalid chain_b_node_id", path, lineno);
                fclose(f);
                return SC_ERR_PARSE;
            }
            out->chain_b.our_node_id = (int)v;
        } else if (strcmp(key, "chain_b_bridge_pubkey") == 0) {
            if (strlen(val) == 64 && crypto_hex_decode(val, out->chain_b.bridge_pubkey, SC_ED25519_PUBKEY_LEN)) {
                out->chain_b.has_bridge_pubkey = true;
            } else {
                set_err(errbuf, errlen, "%s:%d: invalid chain_b_bridge_pubkey hex", path, lineno);
                fclose(f);
                return SC_ERR_PARSE;
            }
        } else if (strcmp(key, "rate_a_to_b_num") == 0) {
            if (!parse_u64(val, &out->rate_a_to_b.rate_num)) {
                set_err(errbuf, errlen, "%s:%d: invalid rate_a_to_b_num", path, lineno);
                fclose(f);
                return SC_ERR_PARSE;
            }
        } else if (strcmp(key, "rate_a_to_b_den") == 0) {
            if (!parse_u64(val, &out->rate_a_to_b.rate_den) || out->rate_a_to_b.rate_den == 0) {
                set_err(errbuf, errlen, "%s:%d: invalid rate_a_to_b_den", path, lineno);
                fclose(f);
                return SC_ERR_PARSE;
            }
        } else if (strcmp(key, "rate_b_to_a_num") == 0) {
            if (!parse_u64(val, &out->rate_b_to_a.rate_num)) {
                set_err(errbuf, errlen, "%s:%d: invalid rate_b_to_a_num", path, lineno);
                fclose(f);
                return SC_ERR_PARSE;
            }
        } else if (strcmp(key, "rate_b_to_a_den") == 0) {
            if (!parse_u64(val, &out->rate_b_to_a.rate_den) || out->rate_b_to_a.rate_den == 0) {
                set_err(errbuf, errlen, "%s:%d: invalid rate_b_to_a_den", path, lineno);
                fclose(f);
                return SC_ERR_PARSE;
            }
        } else {
            set_err(errbuf, errlen, "%s:%d: unknown configuration key '%s'", path, lineno, key);
            fclose(f);
            return SC_ERR_PARSE;
        }
    }

    fclose(f);

    /* Validation */
    if (out->connector_id < 0) {
        set_err(errbuf, errlen, "%s: missing connector_id", path);
        return SC_ERR_INVALID;
    }
    if (out->listen_port == 0) {
        set_err(errbuf, errlen, "%s: missing or invalid listen_port", path);
        return SC_ERR_INVALID;
    }
    if (out->key_path[0] == '\0') {
        set_err(errbuf, errlen, "%s: missing key_path", path);
        return SC_ERR_INVALID;
    }
    if (out->data_dir[0] == '\0') {
        set_err(errbuf, errlen, "%s: missing data_dir", path);
        return SC_ERR_INVALID;
    }
    if (out->chain_a.port == 0 || out->chain_b.port == 0) {
        set_err(errbuf, errlen, "%s: both chain_a and chain_b ports must be configured", path);
        return SC_ERR_INVALID;
    }
    if (out->rate_a_to_b.rate_den == 0 || out->rate_b_to_a.rate_den == 0) {
        set_err(errbuf, errlen, "%s: rate denominators must be > 0", path);
        return SC_ERR_INVALID;
    }

    return SC_OK;
}

sc_err_t cn_config_save_rate(const cn_rate_t *a_to_b, const cn_rate_t *b_to_a,
                              const char *data_dir, char *errbuf, size_t errlen)
{
    if (!a_to_b || !b_to_a || !data_dir) {
        set_err(errbuf, errlen, "null argument");
        return SC_ERR_INVALID;
    }

    char target[CN_MAX_PATH + 64];
    char tmp[CN_MAX_PATH + 64];
    snprintf(target, sizeof(target), "%s/rates.dat", data_dir);
    snprintf(tmp, sizeof(tmp), "%s/rates.dat.tmp", data_dir);

    FILE *f = fopen(tmp, "wb");
    if (!f) {
        set_err(errbuf, errlen, "cannot create %s: %s", tmp, strerror(errno));
        return SC_ERR_IO;
    }

    /* 8-byte magic + 8 bytes reserved */
    uint8_t header[16];
    memset(header, 0, sizeof(header));
    memcpy(header, RATES_FILE_MAGIC, 8);

    if (fwrite(header, 1, sizeof(header), f) != sizeof(header)) {
        set_err(errbuf, errlen, "error writing header to %s", tmp);
        fclose(f);
        unlink(tmp);
        return SC_ERR_IO;
    }

    uint8_t rate_wire[CN_RATE_WIRE_LEN];
    serialize_rate_wire(a_to_b, rate_wire);
    if (fwrite(rate_wire, 1, sizeof(rate_wire), f) != sizeof(rate_wire)) {
        set_err(errbuf, errlen, "error writing rate_a_to_b to %s", tmp);
        fclose(f);
        unlink(tmp);
        return SC_ERR_IO;
    }

    serialize_rate_wire(b_to_a, rate_wire);
    if (fwrite(rate_wire, 1, sizeof(rate_wire), f) != sizeof(rate_wire)) {
        set_err(errbuf, errlen, "error writing rate_b_to_a to %s", tmp);
        fclose(f);
        unlink(tmp);
        return SC_ERR_IO;
    }

    fflush(f);
    int fd = fileno(f);
    if (fd >= 0) {
        fsync(fd);
    }
    fclose(f);

    if (rename(tmp, target) != 0) {
        set_err(errbuf, errlen, "cannot rename %s -> %s: %s", tmp, target, strerror(errno));
        unlink(tmp);
        return SC_ERR_IO;
    }

    return SC_OK;
}

sc_err_t cn_config_load_rate(cn_rate_t *a_to_b, cn_rate_t *b_to_a,
                              const char *data_dir, char *errbuf, size_t errlen)
{
    if (!a_to_b || !b_to_a || !data_dir) {
        set_err(errbuf, errlen, "null argument");
        return SC_ERR_INVALID;
    }

    char path[CN_MAX_PATH + 64];
    snprintf(path, sizeof(path), "%s/rates.dat", data_dir);

    FILE *f = fopen(path, "rb");
    if (!f) {
        if (errno == ENOENT) {
            return SC_ERR_NOT_FOUND;
        }
        set_err(errbuf, errlen, "cannot open %s: %s", path, strerror(errno));
        return SC_ERR_IO;
    }

    uint8_t header[16];
    if (fread(header, 1, sizeof(header), f) != sizeof(header)) {
        set_err(errbuf, errlen, "%s: corrupt rate file (header)", path);
        fclose(f);
        return SC_ERR_PARSE;
    }

    if (memcmp(header, RATES_FILE_MAGIC, 8) != 0) {
        set_err(errbuf, errlen, "%s: invalid magic", path);
        fclose(f);
        return SC_ERR_PARSE;
    }

    uint8_t rate_wire[CN_RATE_WIRE_LEN];
    if (fread(rate_wire, 1, sizeof(rate_wire), f) != sizeof(rate_wire)) {
        set_err(errbuf, errlen, "%s: corrupt rate_a_to_b record", path);
        fclose(f);
        return SC_ERR_PARSE;
    }
    deserialize_rate_wire(a_to_b, rate_wire);

    if (fread(rate_wire, 1, sizeof(rate_wire), f) != sizeof(rate_wire)) {
        set_err(errbuf, errlen, "%s: corrupt rate_b_to_a record", path);
        fclose(f);
        return SC_ERR_PARSE;
    }
    deserialize_rate_wire(b_to_a, rate_wire);

    fclose(f);
    return SC_OK;
}
