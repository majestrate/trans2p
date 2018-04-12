#ifndef I2P_CRYPTO_H
#define I2P_CRYPTO_H
#include "common.h"

struct i2p_privkeybuf
{
  // eddsa signing key
  uint8_t eddsa[64];
  // elgamal encryption key
  uint8_t elg[256];
};

struct i2p_certbuf
{
  uint8_t type;
  uint16_t sz;
  uint8_t * data;
};

struct i2p_dest
{
  uint8_t buf[1024];
  size_t sz;
  uint8_t * enckey;
  uint8_t * sigkey;
  struct i2p_certbuf cert;
};

void i2p_crypto_init(void);
void i2p_crpyto_end(void);

bool i2p_dest_load(struct i2p_dest * dest, uint8_t * data, size_t len);

void i2p_keygen(struct i2p_privkeybuf * priv);

void i2p_privkey_dest(struct i2p_privkeybuf * priv, struct i2p_dest * pub);

void i2p_dest_tob32addr(struct i2p_dest * dest, char * buf, size_t sz);

#endif
