#ifndef I2P_EDDSA_INTERNAL_H
#define I2P_EDDSA_INTERNAL_H
#include "eddsa.h"
#include <ed25519/ed25519.h>

struct i2p_eddsa
{
  unsigned char pub[ed25519_pubkey_SIZE];
  unsigned char priv[ed25519_privkey_SIZE];
};


#endif
