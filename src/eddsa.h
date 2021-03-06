#ifndef I2P_EDDSA_H
#define I2P_EDDSA_H
#include "common.h"

struct i2p_eddsa;

void i2p_eddsa_keygen(struct i2p_eddsa * ed);

bool i2p_eddsa_sign(struct i2p_eddsa * ed, const uint8_t * buf, size_t sz, uint8_t * sig);

bool i2p_eddsa_verify(const uint8_t * pubkey, const uint8_t * buf, size_t sz, const uint8_t * sig);

#endif
