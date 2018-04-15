#ifndef DSA_H
#define DSA_H
#include "common.h"
#include <openssl/dsa.h>

struct i2p_dsa
{
  uint8_t priv[20];
  uint8_t pub[128];
  DSA m_impl;
};

bool i2p_dsa_sign(struct i2p_dsa * dsa, const uint8_t * buf, size_t sz, uint8_t * sig);

#endif
