#define _POSIX_C_SOURCE 200809L
#include "config.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LINE_MAX_LEN 256

/* ------------------------------------------------------------------ */
/* small helpers                                                       */
/* ------------------------------------------------------------------ */

const char *role_str(node_role_t r)
{
    return r == ROLE_VALIDATOR ? "validator" : "normal";
}

static void set_err(char *errbuf, size_t errlen, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

static void set_err(char *errbuf, size_t errlen, const char *fmt, ...)
{
    va_list ap;

    if (!errbuf || errlen == 0)
        return;
    va_start(ap, fmt);
    vsnprintf(errbuf, errlen, fmt, ap);
    va_end(ap);
}

/* Remove leading/trailing whitespace in place; returns pointer into s. */
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

/* Strict integer parse: whole string must be a number in [min, max].
 * (atoi() would silently turn "abc" into 0 - never use it on input.) */
static bool parse_int(const char *s, long min, long max, long *out)
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

static bool copy_str(char *dst, size_t cap, const char *src)
{
    size_t n = strlen(src);

    if (n == 0 || n >= cap)
        return false;
    memcpy(dst, src, n + 1);
    return true;
}

/* Read the next logical line (comment-stripped, trimmed, non-empty).
 * Returns 1 = line available, 0 = EOF, -1 = error (errbuf filled). */
static int next_line(FILE *f, const char *path, int *lineno, char *line,
                     size_t cap, char **content, char *errbuf, size_t errlen)
{
    for (;;) {
        size_t n;
        char *hash;

        if (!fgets(line, (int)cap, f)) {
            if (ferror(f)) {
                set_err(errbuf, errlen, "%s: read error", path);
                return -1;
            }
            return 0;
        }
        (*lineno)++;
        n = strlen(line);
        /* No newline and not at EOF means the line did not fit the buffer. */
        if (n > 0 && line[n - 1] != '\n' && !feof(f)) {
            set_err(errbuf, errlen, "%s:%d: line too long (max %d)", path,
                    *lineno, LINE_MAX_LEN - 1);
            return -1;
        }
        hash = strchr(line, '#');
        if (hash)
            *hash = '\0';
        *content = trim(line);
        if (**content != '\0')
            return 1;
    }
}

/* ------------------------------------------------------------------ */
/* network.conf                                                        */
/* ------------------------------------------------------------------ */

static sc_err_t parse_network_line(char *content, const char *path, int lineno,
                                   network_config_t *out, char *errbuf,
                                   size_t errlen)
{
    char *tok[6];
    char *save = NULL;
    int nt = 0;
    long id, port;
    node_role_t role;
    struct in_addr addr;
    node_info_t *ni;

    for (char *t = strtok_r(content, " \t", &save); t;
         t = strtok_r(NULL, " \t", &save)) {
        if (nt == 6) {
            nt = 7; /* too many */
            break;
        }
        tok[nt++] = t;
    }
    if (nt != 5 || strcmp(tok[0], "node") != 0) {
        set_err(errbuf, errlen,
                "%s:%d: expected 'node <id> <validator|normal> <ipv4> <port>'",
                path, lineno);
        return SC_ERR_PARSE;
    }
    if (!parse_int(tok[1], 0, 999, &id)) {
        set_err(errbuf, errlen, "%s:%d: bad node id '%s' (0..999)", path,
                lineno, tok[1]);
        return SC_ERR_PARSE;
    }
    if (strcmp(tok[2], "validator") == 0) {
        role = ROLE_VALIDATOR;
    } else if (strcmp(tok[2], "normal") == 0) {
        role = ROLE_NORMAL;
    } else {
        set_err(errbuf, errlen, "%s:%d: unknown role '%s'", path, lineno,
                tok[2]);
        return SC_ERR_PARSE;
    }
    if (strlen(tok[3]) >= SC_MAX_HOST || inet_pton(AF_INET, tok[3], &addr) != 1) {
        set_err(errbuf, errlen, "%s:%d: host '%s' is not an IPv4 address",
                path, lineno, tok[3]);
        return SC_ERR_PARSE;
    }
    if (!parse_int(tok[4], 1, 65535, &port)) {
        set_err(errbuf, errlen, "%s:%d: bad port '%s' (1..65535)", path,
                lineno, tok[4]);
        return SC_ERR_PARSE;
    }
    if (out->count >= SC_MAX_NODES) {
        set_err(errbuf, errlen, "%s:%d: too many nodes (max %d)", path, lineno,
                SC_MAX_NODES);
        return SC_ERR_INVALID;
    }
    ni = &out->nodes[out->count++];
    ni->id = (int)id;
    ni->role = role;
    ni->port = (uint16_t)port;
    memcpy(ni->host, tok[3], strlen(tok[3]) + 1);
    return SC_OK;
}

static sc_err_t check_network_unique(const network_config_t *net,
                                     const char *path, char *errbuf,
                                     size_t errlen)
{
    for (size_t i = 0; i < net->count; i++) {
        for (size_t j = i + 1; j < net->count; j++) {
            const node_info_t *a = &net->nodes[i], *b = &net->nodes[j];

            if (a->id == b->id) {
                set_err(errbuf, errlen, "%s: duplicate node id %d", path,
                        a->id);
                return SC_ERR_INVALID;
            }
            if (a->port == b->port && strcmp(a->host, b->host) == 0) {
                set_err(errbuf, errlen,
                        "%s: duplicate address %s:%u (nodes %d and %d)", path,
                        a->host, (unsigned)a->port, a->id, b->id);
                return SC_ERR_INVALID;
            }
        }
    }
    return SC_OK;
}

sc_err_t config_load_network(const char *path, network_config_t *out,
                             char *errbuf, size_t errlen)
{
    FILE *f;
    char line[LINE_MAX_LEN];
    char *content;
    int lineno = 0, rc;
    sc_err_t err = SC_OK;

    memset(out, 0, sizeof *out);
    f = fopen(path, "r");
    if (!f) {
        set_err(errbuf, errlen, "cannot open %s: %s", path, strerror(errno));
        return SC_ERR_IO;
    }
    while ((rc = next_line(f, path, &lineno, line, sizeof line, &content,
                           errbuf, errlen)) == 1) {
        err = parse_network_line(content, path, lineno, out, errbuf, errlen);
        if (err != SC_OK)
            goto done;
    }
    if (rc < 0) {
        err = SC_ERR_PARSE;
        goto done;
    }
    if (out->count == 0) {
        set_err(errbuf, errlen, "%s: no nodes defined", path);
        err = SC_ERR_INVALID;
        goto done;
    }
    err = check_network_unique(out, path, errbuf, errlen);
done:
    fclose(f);
    if (err != SC_OK)
        memset(out, 0, sizeof *out);
    return err;
}

/* ------------------------------------------------------------------ */
/* node_N.conf                                                         */
/* ------------------------------------------------------------------ */

sc_err_t config_load_node(const char *path, node_config_t *out, char *errbuf,
                          size_t errlen)
{
    FILE *f;
    char line[LINE_MAX_LEN];
    char *content;
    int lineno = 0, rc;
    bool have_id = false, have_key = false, have_dir = false;
    sc_err_t err = SC_OK;

    memset(out, 0, sizeof *out);
    f = fopen(path, "r");
    if (!f) {
        set_err(errbuf, errlen, "cannot open %s: %s", path, strerror(errno));
        return SC_ERR_IO;
    }
    while ((rc = next_line(f, path, &lineno, line, sizeof line, &content,
                           errbuf, errlen)) == 1) {
        char *eq = strchr(content, '=');
        char *key, *val;
        long id;

        if (!eq) {
            set_err(errbuf, errlen, "%s:%d: expected 'key = value'", path,
                    lineno);
            err = SC_ERR_PARSE;
            goto done;
        }
        *eq = '\0';
        key = trim(content);
        val = trim(eq + 1);

        if (strcmp(key, "node_id") == 0) {
            if (have_id || !parse_int(val, 0, 999, &id)) {
                set_err(errbuf, errlen, "%s:%d: %s node_id '%s'", path, lineno,
                        have_id ? "duplicate" : "bad", val);
                err = SC_ERR_PARSE;
                goto done;
            }
            out->node_id = (int)id;
            have_id = true;
        } else if (strcmp(key, "key_path") == 0) {
            if (have_key || !copy_str(out->key_path, sizeof out->key_path, val)) {
                set_err(errbuf, errlen,
                        "%s:%d: key_path is duplicate, empty, or too long",
                        path, lineno);
                err = SC_ERR_PARSE;
                goto done;
            }
            have_key = true;
        } else if (strcmp(key, "data_dir") == 0) {
            if (have_dir || !copy_str(out->data_dir, sizeof out->data_dir, val)) {
                set_err(errbuf, errlen,
                        "%s:%d: data_dir is duplicate, empty, or too long",
                        path, lineno);
                err = SC_ERR_PARSE;
                goto done;
            }
            have_dir = true;
        } else {
            set_err(errbuf, errlen, "%s:%d: unknown key '%s'", path, lineno,
                    key);
            err = SC_ERR_PARSE;
            goto done;
        }
    }
    if (rc < 0) {
        err = SC_ERR_PARSE;
        goto done;
    }
    if (!have_id || !have_key || !have_dir) {
        set_err(errbuf, errlen, "%s: missing required key '%s'", path,
                !have_id ? "node_id" : (!have_key ? "key_path" : "data_dir"));
        err = SC_ERR_INVALID;
    }
done:
    fclose(f);
    if (err != SC_OK)
        memset(out, 0, sizeof *out);
    return err;
}

/* ------------------------------------------------------------------ */
/* queries                                                             */
/* ------------------------------------------------------------------ */

const node_info_t *config_find_node(const network_config_t *net, int id)
{
    if (!net)
        return NULL;
    for (size_t i = 0; i < net->count; i++)
        if (net->nodes[i].id == id)
            return &net->nodes[i];
    return NULL;
}

bool config_node_is_validator(const network_config_t *net, int id)
{
    const node_info_t *ni = config_find_node(net, id);

    return ni != NULL && ni->role == ROLE_VALIDATOR;
}

sc_err_t config_check_topology(const network_config_t *net, size_t validators,
                               size_t normals, char *errbuf, size_t errlen)
{
    size_t v = 0, n = 0;

    for (size_t i = 0; i < net->count; i++) {
        if (net->nodes[i].role == ROLE_VALIDATOR)
            v++;
        else
            n++;
    }
    if (v != validators || n != normals) {
        set_err(errbuf, errlen,
                "topology must be %zu validators + %zu normal nodes, found %zu + %zu",
                validators, normals, v, n);
        return SC_ERR_INVALID;
    }
    return SC_OK;
}
