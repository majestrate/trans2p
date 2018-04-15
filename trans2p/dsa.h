#ifndef DSA_H
#define DSA_H
#include "common.h"

struct i2p_dsa;

void i2p_dsa_init(struct i2p_dsa * dsa, uint8_t * priv, uint8_t * pub);

bool i2p_dsa_sign(struct i2p_dsa * dsa, const uint8_t * buf, size_t sz, uint8_t * sig);

#endif
