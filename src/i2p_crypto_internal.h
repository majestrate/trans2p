#ifndef I2P_CRYPTO_INTERNAL_H
#define I2P_CRYPTO_INTERNAL_H
#include "i2p_crypto.h"
#include "dsa_internal.h"
#include "eddsa_internal.h"
#include "elg_internal.h"

struct i2p_privkeybuf
{
  uint16_t sigtype;
  uint16_t enctype;
  // eddsa signing keypair
  struct i2p_eddsa eddsa;
  // elgamal encryption keypair
  struct i2p_elg elg;
  // dsa signing keypair
  struct i2p_dsa dsa;
};

struct i2p_certbuf
{
  uint8_t type;
  uint16_t sz;
  uint8_t * data;
};


struct i2p_dest
{
  uint8_t buf[512];
  size_t sz;
  uint16_t sigtype;
  uint16_t enctype;
  uint8_t * enckey;
  uint8_t * sigkey;
  struct i2p_certbuf cert;
};



#endif
