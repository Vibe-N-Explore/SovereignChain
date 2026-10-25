/* connector_types.h - Core types for the SovereignChain connector network.
 *
 * The connector network bridges two independent SovereignChain instances
 * (Chain A and Chain B). It provides:
 *   1. Cross-chain activity feed: visibility of ordinary same-chain txs
 *   2. Cross-chain value transfers: explicit user-initiated bridge operations
 *
 * All integers are big-endian on the wire. No floating-point arithmetic.
 * Ed25519 + SHA-256 via OpenSSL EVP (same as the blockchain).
 */
#ifndef CN_TYPES_H
#define CN_TYPES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Pull in existing blockchain types */
#include "../../src/crypto.h"
#include "../../src/err.h"
#include "../../src/tx.h"

/* ---- Chain identifiers ---- */
#define CN_CHAIN_A       0
#define CN_CHAIN_B       1
#define CN_CHAIN_UNKNOWN 255

/* ---- Connector network limits ---- */
#define CN_MAX_PEERS     16
#define CN_MAX_HOST      64
#define CN_MAX_PATH      256

/* ---- Wire frame constants (same format as blockchain net.c) ----
 * Header: payload_len(4 BE) | type(2 BE) | reserved(2)
 * Max payload: 64 KB
 */
#define CN_NET_HEADER_LEN   8
#define CN_NET_MAX_PAYLOAD  (64 * 1024)

/* ---- Message types for connector-to-connector protocol ---- */
typedef enum {
    /* Handshake (same 3-step Ed25519 challenge-response as blockchain) */
    CN_MSG_HELLO_INIT    = 1,  /* connector->peer: id(u32) + pubkey(32)            */
    CN_MSG_HELLO_CHAL    = 2,  /* peer->connector: nonce(32)+pubkey(32)+sig(64)    */
    CN_MSG_HELLO_RESP    = 3,  /* connector->peer: sig(nonce)(64)                  */

    CN_MSG_PING          = 4,
    CN_MSG_PONG          = 5,

    /* Activity feed propagation */
    CN_MSG_ACTIVITY      = 6,  /* cn_activity_record_t serialized (299 bytes)     */

    /* Cross-chain value transfer protocol */
    CN_MSG_TRANSFER_REQ  = 7,  /* propose a transfer: transfer_id + transfer core  */
    CN_MSG_TRANSFER_VOTE = 8,  /* vote on a transfer: transfer_id(32)+sig(64)      */
    CN_MSG_TRANSFER_CERT = 9,  /* approved cert: transfer_id(32)+count(4)+sigs...  */

    /* Sync/recovery: catch up missed activity after reconnect */
    CN_MSG_SYNC_REQ      = 10, /* since_seq(8 BE)                                  */
    CN_MSG_SYNC_RESP     = 11, /* count(4 BE) + count*activity_records              */

    /* Exchange rate management */
    CN_MSG_RATE_UPDATE   = 12, /* cn_rate_t serialized                             */
    CN_MSG_RATE_VOTE     = 13, /* rate_version(8 BE)+connector_pubkey(32)+sig(64)  */
} cn_msg_type_t;

/* ---- Activity record status ---- */
typedef enum {
    CN_STATUS_PENDING     = 0,  /* observed but not yet verified on-chain           */
    CN_STATUS_VERIFIED    = 1,  /* signature verified, tx known to be valid         */
    CN_STATUS_FINALIZED   = 2,  /* included in a certified DAG vertex               */
    CN_STATUS_REJECTED    = 3,  /* invalid or double-spend                          */
    CN_STATUS_UNAVAILABLE = 4,  /* source chain did not provide this field          */
} cn_activity_status_t;

/* ---- Transaction type in the activity feed ---- */
typedef enum {
    CN_TX_TYPE_SAME_CHAIN  = 0,  /* ordinary transaction within one chain           */
    CN_TX_TYPE_CROSS_CHAIN = 1,  /* cross-chain transfer (to bridge escrow)         */
} cn_tx_type_t;

/* ---- Transfer state machine ---- */
typedef enum {
    CN_XFR_DETECTED              = 0,
    CN_XFR_SOURCE_VERIFIED       = 1,
    CN_XFR_APPROVED              = 2,
    CN_XFR_DESTINATION_SUBMITTED = 3,
    CN_XFR_DESTINATION_CONFIRMED = 4,
    CN_XFR_COMPLETED             = 5,
    CN_XFR_FAILED                = 6,
    CN_XFR_AMBIGUOUS             = 7,  /* timeout: outcome unknown; do NOT retry blindly */
} cn_transfer_state_t;

/* ---- Cross-chain activity record ----
 *
 * One record per observed transaction. Propagated to all connectors.
 * Activity records are OBSERVATIONS only; they never cause value to
 * be created or moved on the other chain.
 *
 * record_id = SHA-256("ACTIVITY/v1" || source_chain(1) || tx_hash(32))
 *
 * Wire layout (299 bytes total):
 *   record_id(32) + source_chain(1) + tx_hash(32) + sender(32) +
 *   recipient(32) + amount(8) + fee(8) + nonce(8) + tx_type(1) +
 *   source_round(8) + source_vertex_hash(32) + status(1) +
 *   observed_at(8) + reporter_pubkey(32) + reporter_sig(64)
 */
#define CN_ACTIVITY_WIRE_LEN (32 + 1 + 32 + 32 + 32 + 8 + 8 + 8 + 1 + 8 + 32 + 1 + 8 + 32 + 64)

typedef struct {
    uint8_t  record_id[SC_SHA256_LEN];    /* stable id: SHA-256("ACTIVITY/v1"||source_chain||tx_hash) */
    uint8_t  source_chain;                /* CN_CHAIN_A or CN_CHAIN_B */
    uint8_t  tx_hash[SC_SHA256_LEN];      /* native transaction hash from source chain */
    uint8_t  sender[SC_ED25519_PUBKEY_LEN];
    uint8_t  recipient[SC_ED25519_PUBKEY_LEN];
    uint64_t amount;
    uint64_t fee;
    uint64_t nonce;
    uint8_t  tx_type;                     /* cn_tx_type_t */
    uint64_t source_round;                /* DAG round if available, 0 if not */
    uint8_t  source_vertex_hash[SC_SHA256_LEN]; /* vertex containing this tx, zeros if unavailable */
    uint8_t  status;                      /* cn_activity_status_t */
    int64_t  observed_at;                 /* Unix timestamp */
    uint8_t  reporter_pubkey[SC_ED25519_PUBKEY_LEN]; /* which connector first reported */
    uint8_t  reporter_sig[SC_ED25519_SIG_LEN];        /* signature over record_id||status||observed_at */
} cn_activity_record_t;

/* ---- Exchange rate: rational, no floating point ----
 *
 * Rate for A->B means: 1 unit on A = (rate_num / rate_den) units on B.
 * rate_den must be > 0. Overflow is checked before application.
 * version increments monotonically; updater_sig covers the rate values.
 *
 * Wire layout (128 bytes):
 *   rate_num(8) + rate_den(8) + version(8) + updated_at(8) +
 *   updater_pubkey(32) + updater_sig(64)
 */
#define CN_RATE_WIRE_LEN (8 + 8 + 8 + 8 + 32 + 64)

typedef struct {
    uint64_t rate_num;      /* numerator */
    uint64_t rate_den;      /* denominator (must be >0) */
    uint64_t version;       /* monotonically increasing rate version */
    int64_t  updated_at;    /* Unix timestamp */
    uint8_t  updater_pubkey[SC_ED25519_PUBKEY_LEN];
    uint8_t  updater_sig[SC_ED25519_SIG_LEN]; /* sig over "RATE/v1"||rate_num||rate_den||version */
} cn_rate_t;

/* ---- Cross-chain transfer record ----
 *
 * transfer_id = SHA-256("XFER/v1" || source_chain(1) || source_tx_hash(32))
 *
 * The rate is frozen at initiation time so later rate changes cannot
 * silently alter an in-flight transfer.
 */
#define CN_TRANSFER_MAX_VOTES CN_MAX_PEERS
#define CN_TRANSFER_CORE_WIRE_LEN (32 + 1 + 1 + 32 + 32 + 32 + 8 + 8 + 8 + 8 + 8 + 1 + 8 + 8)

typedef struct {
    uint8_t  transfer_id[SC_SHA256_LEN];   /* SHA-256("XFER/v1"||src_chain||tx_hash) */
    uint8_t  source_chain;
    uint8_t  dest_chain;
    uint8_t  source_tx_hash[SC_SHA256_LEN];
    uint8_t  sender[SC_ED25519_PUBKEY_LEN];
    uint8_t  recipient[SC_ED25519_PUBKEY_LEN];
    uint64_t source_amount;
    uint64_t dest_amount;          /* calculated from rate at time of initiation */
    uint64_t rate_num;             /* frozen rate numerator */
    uint64_t rate_den;             /* frozen rate denominator */
    uint64_t rate_version;         /* rate version used */
    uint8_t  state;                /* cn_transfer_state_t */
    int64_t  initiated_at;
    int64_t  last_updated_at;
    /* Certificate fields (filled when APPROVED) */
    size_t   cert_sig_count;
    uint8_t  cert_sigs[CN_MAX_PEERS][SC_ED25519_SIG_LEN];
    uint8_t  cert_signers[CN_MAX_PEERS][SC_ED25519_PUBKEY_LEN];
    /* Destination tx (filled when DESTINATION_SUBMITTED) */
    uint8_t  dest_tx_hash[SC_SHA256_LEN];
    bool     dest_tx_hash_valid;
    char     error_detail[256];
} cn_transfer_t;

/* Field aliases for convenience */
#define vote_count cert_sig_count
#define vote_sigs cert_sigs
#define vote_pubkeys cert_signers

/* ---- Connector peer configuration entry ---- */
typedef struct {
    int      id;
    char     host[CN_MAX_HOST];
    uint16_t port;
    uint8_t  pubkey[SC_ED25519_PUBKEY_LEN];
    bool     has_pubkey;
} cn_peer_info_t;

/* ---- Chain connection configuration ----
 *
 * The connector connects to one node in each chain's network.
 * our_node_id: the node_id this connector uses in that chain's network.conf.
 * The chain node validates the connector's pubkey against network.conf,
 * so the connector keypair MUST be registered there as a normal node.
 *
 * bridge_pubkey: the Ed25519 public key of the bridge escrow account on
 * this chain. Any transaction sent TO this key is treated as a cross-chain
 * transfer initiation (CN_TX_TYPE_CROSS_CHAIN).
 */
typedef struct {
    uint8_t  chain_id;            /* CN_CHAIN_A or CN_CHAIN_B */
    char     host[CN_MAX_HOST];
    uint16_t port;
    uint8_t  pubkey[SC_ED25519_PUBKEY_LEN]; /* chain node's pubkey for auth */
    bool     has_pubkey;
    int      our_node_id;         /* our node_id within that chain's network.conf */
    uint8_t  bridge_pubkey[SC_ED25519_PUBKEY_LEN]; /* bridge escrow account pubkey */
    bool     has_bridge_pubkey;
} cn_chain_cfg_t;

#define node_pubkey pubkey
#define has_node_pubkey has_pubkey

/* ---- Full connector configuration ---- */
typedef struct {
    int          connector_id;
    char         key_path[CN_MAX_PATH];
    char         data_dir[CN_MAX_PATH];
    char         listen_host[CN_MAX_HOST];
    uint16_t     listen_port;
    cn_chain_cfg_t chain_a;
    cn_chain_cfg_t chain_b;
    cn_peer_info_t peers[CN_MAX_PEERS];
    size_t       peer_count;
    /* Exchange rates (A->B and B->A) */
    cn_rate_t    rate_a_to_b;
    cn_rate_t    rate_b_to_a;
    /* Quorum: number of connector votes required for transfer approval */
    int          quorum;
    /* Logging */
    int          log_level;       /* 0=debug,1=info,2=warn,3=error */
} cn_config_t;

#endif /* CN_TYPES_H */
