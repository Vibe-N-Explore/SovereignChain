/* cn_config.h - Connector configuration loading, validation, and rate persistence. */
#ifndef CN_CONFIG_H
#define CN_CONFIG_H

#include "connector_types.h"

/*
 * Load and validate connector.conf.
 *
 * connector.conf format:
 *   connector_id     = 0
 *   key_path         = connector/keys/connector0.key
 *   data_dir         = connector/data/connector0
 *   listen_host      = 127.0.0.1
 *   listen_port      = 8000
 *   quorum           = 2
 *   log_level        = 1
 *
 *   chain_a_host          = 127.0.0.1
 *   chain_a_port          = 9000
 *   chain_a_pubkey        = <64-char hex>
 *   chain_a_node_id       = 0
 *   chain_a_bridge_pubkey = <64-char hex>
 *
 *   chain_b_host          = 127.0.0.1
 *   chain_b_port          = 19000
 *   chain_b_pubkey        = <64-char hex>
 *   chain_b_node_id       = 0
 *   chain_b_bridge_pubkey = <64-char hex>
 *
 *   rate_a_to_b_num = 1
 *   rate_a_to_b_den = 1
 *   rate_b_to_a_num = 1
 *   rate_b_to_a_den = 1
 *
 *   peer <id> <host> <port> [<pubkey_hex>]
 */
sc_err_t cn_config_load(const char *path, cn_config_t *out,
                         char *errbuf, size_t errlen);

/* Save updated exchange rates to data_dir/rates.dat atomically. */
sc_err_t cn_config_save_rate(const cn_rate_t *a_to_b, const cn_rate_t *b_to_a,
                              const char *data_dir, char *errbuf, size_t errlen);

/* Load rates from data_dir/rates.dat if it exists. Returns SC_ERR_NOT_FOUND if absent. */
sc_err_t cn_config_load_rate(cn_rate_t *a_to_b, cn_rate_t *b_to_a,
                              const char *data_dir, char *errbuf, size_t errlen);

/* Plural aliases for convenience */
#define cn_config_save_rates cn_config_save_rate
#define cn_config_load_rates cn_config_load_rate

#endif /* CN_CONFIG_H */
