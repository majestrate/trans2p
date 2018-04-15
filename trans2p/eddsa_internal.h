#ifndef I2P_EDDSA_INTERNAL_H
#define I2P_EDDSA_INTERNAL_H
#include "eddsa.h"

struct i2p_eddsa
{
  uint8_t priv[64];
  uint8_t pub[32];
};


#endif
