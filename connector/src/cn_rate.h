/* cn_rate.h - Exchange rate management and validation. */
#ifndef CN_RATE_H
#define CN_RATE_H

#include "connector_types.h"

/* Sign a rate update (domain: "RATE/v1" || rate_num(8 BE) || rate_den(8 BE) || version(8 BE)) */
sc_err_t cn_rate_sign(cn_rate_t *rate, const sc_keypair_t *my_kp);

/* Verify rate signature */
sc_err_t cn_rate_verify(const cn_rate_t *rate);

/* Validate rate values (den>0, no overflow in multiply with max uint64) */
sc_err_t cn_rate_validate(const cn_rate_t *rate);

/* Serialize/deserialize */
sc_err_t cn_rate_serialize(const cn_rate_t *rate, uint8_t *buf, size_t buflen, size_t *written);
sc_err_t cn_rate_deserialize(cn_rate_t *rate, const uint8_t *buf, size_t len);

/* Save rates to data_dir/rates.dat atomically */
sc_err_t cn_rate_save(const cn_rate_t *a_to_b, const cn_rate_t *b_to_a, const char *data_dir);

/* Load rates from data_dir/rates.dat */
sc_err_t cn_rate_load(cn_rate_t *a_to_b, cn_rate_t *b_to_a, const char *data_dir);

#endif /* CN_RATE_H */
