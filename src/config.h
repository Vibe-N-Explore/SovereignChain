/* config.h - node configuration, roles, and validator permissions.
 *
 * Two files describe a running node:
 *
 *  1. network.conf (shared by all nodes - the single source of truth for
 *     roles AND public keys). One line per node:
 *         node <id> <validator|normal> <ipv4-address> <port> <pubkey_hex>
 *     pubkey_hex is the 64-character lowercase hex encoding of the node's
 *     32-byte Ed25519 public key. It is the PINNED key used for crypto
 *     enforcement: validator messages are accepted only if their signatures
 *     verify against this value.
 *
 *  2. node_N.conf (private to one node):
 *         node_id  = <id>
 *         key_path = <path to this node's identity key>   (used from Phase 3)
 *         data_dir = <directory for persistent data>      (used from Phase 8)
 *
 * A node's ROLE is looked up in network.conf by its id. It is deliberately
 * NOT a field of node_N.conf, so a node cannot simply "claim" a role.
 * Cryptographic enforcement (Phase 3+): validator messages must carry
 * signatures that verify against the validator keys pinned here.
 * See config_node_is_validator().
 *
 * Trust: all text in these files is parsed defensively (bounded lengths,
 * strict number parsing), even though in the MVP they are local files.
 */
#ifndef SC_CONFIG_H
#define SC_CONFIG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "err.h"

#define SC_MAX_NODES   16
#define SC_MAX_HOST    64
#define SC_MAX_PATH    256

/* Raw 32-byte Ed25519 public key. Zero-initialised means "not set". */
#define SC_ED25519_PUBKEY_LEN 32

typedef enum { ROLE_VALIDATOR = 0, ROLE_NORMAL = 1 } node_role_t;

typedef struct {
    int         id;
    node_role_t role;
    char        host[SC_MAX_HOST];   /* IPv4 dotted-quad (no DNS in the MVP) */
    uint16_t    port;
    uint8_t     pubkey[SC_ED25519_PUBKEY_LEN]; /* pinned Ed25519 public key */
    bool        has_pubkey;          /* false until Phase 3 key material added */
} node_info_t;

typedef struct {
    node_info_t nodes[SC_MAX_NODES];
    size_t      count;
} network_config_t;

typedef struct {
    int  node_id;
    char key_path[SC_MAX_PATH];
    char data_dir[SC_MAX_PATH];
} node_config_t;

const char *role_str(node_role_t r);

/* Load and validate network.conf. On failure returns an error code and
 * writes a human-readable reason into errbuf. *out is zeroed first. */
sc_err_t config_load_network(const char *path, network_config_t *out,
                             char *errbuf, size_t errlen);

/* Load and validate one node_N.conf. */
sc_err_t config_load_node(const char *path, node_config_t *out,
                          char *errbuf, size_t errlen);

/* Returns the entry for 'id', or NULL if the id is not in the network. */
const node_info_t *config_find_node(const network_config_t *net, int id);

/* THE one function that decides validator permission. Later phases call
 * this before any validator-only action (build a vertex, sign a vote).
 * Unknown ids are never validators. */
bool config_node_is_validator(const network_config_t *net, int id);

/* Project rule: the development topology is fixed at exactly
 * 'validators' validators + 'normals' normal nodes. */
sc_err_t config_check_topology(const network_config_t *net, size_t validators,
                               size_t normals, char *errbuf, size_t errlen);

#endif /* SC_CONFIG_H */
