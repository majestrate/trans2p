#ifndef DSA_INTERNAL_H
#define DSA_INTERNAL_H
#include "dsa.h"
#include <openssl/dsa.h>

struct i2p_dsa
{
  uint8_t priv[20];
  uint8_t pub[128];
};

#endif
