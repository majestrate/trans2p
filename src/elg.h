#ifndef ELG_H
#define ELG_H
#include "common.h"


struct i2p_elg
{
  uint8_t priv[256];
  uint8_t pub[256];
};

void i2p_elg_keygen(struct i2p_elg * elg);

#endif
