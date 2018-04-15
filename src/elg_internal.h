#ifndef ELG_INTERNAL_H
#define ELG_INTERNAL_H
#include "elg.h"

struct i2p_elg
{
  uint8_t priv[256];
  uint8_t pub[256];
};

#endif
