#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "config.h"
#include "testutil.h"

#define GOOD_NET                                                             \
    "# comment line\n"                                                       \
    "node 0 validator 127.0.0.1 9000\n"                                      \
    "node 1 validator 127.0.0.1 9001   # trailing comment\n"                 \
    "\n"                                                                     \
    "node 2 normal 127.0.0.1 9002\n"                                         \
    "node 3 normal 127.0.0.1 9003\n"                                         \
    "node 4 normal 127.0.0.1 9004\n"                                         \
    "node 5 normal 127.0.0.1 9005\n"

#define GOOD_NODE                                                            \
    "node_id = 2\n"                                                          \
    "key_path = keys/node2.key\n"                                            \
    "data_dir = data/node2\n"

/* Write 'content' to a fresh temp file; path is returned in 'path'. */
static void write_tmp(const char *content, char *path, size_t cap)
{
    int fd;
    FILE *f;

    snprintf(path, cap, "/tmp/sc_test_XXXXXX");
    fd = mkstemp(path);
    if (fd < 0) {
        perror("mkstemp");
        exit(2);
    }
    f = fdopen(fd, "w");
    fputs(content, f);
    fclose(f);
}

static sc_err_t load_net_text(const char *text, network_config_t *net,
                              char *err, size_t errlen)
{
    char path[64];
    sc_err_t rc;

    write_tmp(text, path, sizeof path);
    rc = config_load_network(path, net, err, errlen);
    unlink(path);
    return rc;
}

static sc_err_t load_node_text(const char *text, node_config_t *cfg, char *err,
                               size_t errlen)
{
    char path[64];
    sc_err_t rc;

    write_tmp(text, path, sizeof path);
    rc = config_load_node(path, cfg, err, errlen);
    unlink(path);
    return rc;
}

/* ---------------- network.conf ---------------- */

static void test_network_valid(void)
{
    network_config_t net;
    char err[256] = "";

    CHECK(load_net_text(GOOD_NET, &net, err, sizeof err) == SC_OK);
    CHECK(net.count == 6);
    CHECK(net.nodes[0].id == 0 && net.nodes[0].role == ROLE_VALIDATOR);
    CHECK(net.nodes[5].id == 5 && net.nodes[5].role == ROLE_NORMAL);
    CHECK(net.nodes[5].port == 9005);
    CHECK(strcmp(net.nodes[2].host, "127.0.0.1") == 0);
}

static void test_network_duplicate_id(void)
{
    network_config_t net;
    char err[256] = "";

    CHECK(load_net_text(GOOD_NET "node 2 normal 127.0.0.1 9099\n", &net, err,
                        sizeof err) == SC_ERR_INVALID);
    CHECK_CONTAINS(err, "duplicate node id 2");
    CHECK(net.count == 0); /* output is cleared on failure */
}

static void test_network_duplicate_address(void)
{
    network_config_t net;
    char err[256] = "";

    CHECK(load_net_text("node 0 validator 127.0.0.1 9000\n"
                        "node 1 validator 127.0.0.1 9000\n",
                        &net, err, sizeof err) == SC_ERR_INVALID);
    CHECK_CONTAINS(err, "duplicate address");
}

static void test_network_unknown_role(void)
{
    network_config_t net;
    char err[256] = "";

    CHECK(load_net_text("node 0 observer 127.0.0.1 9000\n", &net, err,
                        sizeof err) == SC_ERR_PARSE);
    CHECK_CONTAINS(err, "unknown role 'observer'");
}

static void test_network_bad_numbers(void)
{
    network_config_t net;
    char err[256] = "";

    CHECK(load_net_text("node 0 normal 127.0.0.1 0\n", &net, err, sizeof err) ==
          SC_ERR_PARSE);
    CHECK(load_net_text("node 0 normal 127.0.0.1 70000\n", &net, err,
                        sizeof err) == SC_ERR_PARSE);
    CHECK(load_net_text("node 0 normal 127.0.0.1 90x0\n", &net, err,
                        sizeof err) == SC_ERR_PARSE);
    CHECK(load_net_text("node -1 normal 127.0.0.1 9000\n", &net, err,
                        sizeof err) == SC_ERR_PARSE);
    CHECK(load_net_text("node abc normal 127.0.0.1 9000\n", &net, err,
                        sizeof err) == SC_ERR_PARSE);
}

static void test_network_bad_host(void)
{
    network_config_t net;
    char err[256] = "";

    CHECK(load_net_text("node 0 normal localhost 9000\n", &net, err,
                        sizeof err) == SC_ERR_PARSE);
    CHECK(load_net_text("node 0 normal 999.1.1.1 9000\n", &net, err,
                        sizeof err) == SC_ERR_PARSE);
}

static void test_network_wrong_token_count(void)
{
    network_config_t net;
    char err[256] = "";

    CHECK(load_net_text("node 0 normal 127.0.0.1\n", &net, err, sizeof err) ==
          SC_ERR_PARSE);
    CHECK(load_net_text("node 0 normal 127.0.0.1 9000 extra\n", &net, err,
                        sizeof err) == SC_ERR_PARSE);
    CHECK(load_net_text("peer 0 normal 127.0.0.1 9000\n", &net, err,
                        sizeof err) == SC_ERR_PARSE);
}

static void test_network_empty_and_missing(void)
{
    network_config_t net;
    char err[256] = "";

    CHECK(load_net_text("# nothing here\n\n", &net, err, sizeof err) ==
          SC_ERR_INVALID);
    CHECK(config_load_network("/tmp/does/not/exist.conf", &net, err,
                              sizeof err) == SC_ERR_IO);
}

static void test_network_too_many_nodes(void)
{
    network_config_t net;
    char err[256] = "";
    char text[2048] = "";
    char one[64];

    for (int i = 0; i < SC_MAX_NODES + 1; i++) {
        snprintf(one, sizeof one, "node %d normal 127.0.0.1 %d\n", i, 9000 + i);
        strcat(text, one);
    }
    CHECK(load_net_text(text, &net, err, sizeof err) == SC_ERR_INVALID);
    CHECK_CONTAINS(err, "too many nodes");
}

static void test_network_line_too_long(void)
{
    network_config_t net;
    char err[256] = "";
    char text[600];

    memset(text, 'a', sizeof text - 2);
    text[sizeof text - 2] = '\n';
    text[sizeof text - 1] = '\0';
    CHECK(load_net_text(text, &net, err, sizeof err) == SC_ERR_PARSE);
    CHECK_CONTAINS(err, "line too long");
}

/* ---------------- node_N.conf ---------------- */

static void test_node_valid(void)
{
    node_config_t cfg;
    char err[256] = "";

    CHECK(load_node_text(GOOD_NODE, &cfg, err, sizeof err) == SC_OK);
    CHECK(cfg.node_id == 2);
    CHECK(strcmp(cfg.key_path, "keys/node2.key") == 0);
    CHECK(strcmp(cfg.data_dir, "data/node2") == 0);
}

static void test_node_missing_key_path(void)
{
    node_config_t cfg;
    char err[256] = "";

    CHECK(load_node_text("node_id = 2\ndata_dir = data/node2\n", &cfg, err,
                         sizeof err) == SC_ERR_INVALID);
    CHECK_CONTAINS(err, "missing required key 'key_path'");
}

static void test_node_empty_key_path(void)
{
    node_config_t cfg;
    char err[256] = "";

    CHECK(load_node_text("node_id = 2\nkey_path =\ndata_dir = d\n", &cfg, err,
                         sizeof err) == SC_ERR_PARSE);
}

static void test_node_bad_entries(void)
{
    node_config_t cfg;
    char err[256] = "";

    CHECK(load_node_text(GOOD_NODE "node_id = 3\n", &cfg, err, sizeof err) ==
          SC_ERR_PARSE); /* duplicate key */
    CHECK(load_node_text(GOOD_NODE "role = validator\n", &cfg, err,
                         sizeof err) == SC_ERR_PARSE); /* unknown key */
    CHECK_CONTAINS(err, "unknown key 'role'");
    CHECK(load_node_text("node_id = x\nkey_path = k\ndata_dir = d\n", &cfg,
                         err, sizeof err) == SC_ERR_PARSE);
    CHECK(load_node_text("node_id 2\n", &cfg, err, sizeof err) ==
          SC_ERR_PARSE); /* no '=' */
}

/* A node cannot promote itself by writing 'role' in its own file. */
static void test_node_cannot_claim_role(void)
{
    node_config_t cfg;
    char err[256] = "";

    CHECK(load_node_text(GOOD_NODE "role = validator\n", &cfg, err,
                         sizeof err) != SC_OK);
}

/* ---------------- role gating & topology ---------------- */

static void test_role_gating(void)
{
    network_config_t net;
    char err[256] = "";

    CHECK(load_net_text(GOOD_NET, &net, err, sizeof err) == SC_OK);
    CHECK(config_node_is_validator(&net, 0));
    CHECK(config_node_is_validator(&net, 1));
    for (int id = 2; id <= 5; id++)
        CHECK(!config_node_is_validator(&net, id));
    CHECK(!config_node_is_validator(&net, 99)); /* unknown id: never */
    CHECK(!config_node_is_validator(NULL, 0));  /* NULL-safe */
    CHECK(config_find_node(&net, 3) != NULL);
    CHECK(config_find_node(&net, 6) == NULL);
}

static void test_topology(void)
{
    network_config_t net;
    char err[256] = "";

    CHECK(load_net_text(GOOD_NET, &net, err, sizeof err) == SC_OK);
    CHECK(config_check_topology(&net, 2, 4, err, sizeof err) == SC_OK);
    CHECK(config_check_topology(&net, 3, 3, err, sizeof err) == SC_ERR_INVALID);
    CHECK_CONTAINS(err, "found 2 + 4");

    CHECK(load_net_text("node 0 validator 127.0.0.1 9000\n"
                        "node 1 validator 127.0.0.1 9001\n"
                        "node 2 validator 127.0.0.1 9002\n"
                        "node 3 normal 127.0.0.1 9003\n"
                        "node 4 normal 127.0.0.1 9004\n"
                        "node 5 normal 127.0.0.1 9005\n",
                        &net, err, sizeof err) == SC_OK);
    CHECK(config_check_topology(&net, 2, 4, err, sizeof err) == SC_ERR_INVALID);
}

int main(void)
{
    printf("test_config\n");
    RUN(test_network_valid);
    RUN(test_network_duplicate_id);
    RUN(test_network_duplicate_address);
    RUN(test_network_unknown_role);
    RUN(test_network_bad_numbers);
    RUN(test_network_bad_host);
    RUN(test_network_wrong_token_count);
    RUN(test_network_empty_and_missing);
    RUN(test_network_too_many_nodes);
    RUN(test_network_line_too_long);
    RUN(test_node_valid);
    RUN(test_node_missing_key_path);
    RUN(test_node_empty_key_path);
    RUN(test_node_bad_entries);
    RUN(test_node_cannot_claim_role);
    RUN(test_role_gating);
    RUN(test_topology);
    return TEST_SUMMARY();
}
