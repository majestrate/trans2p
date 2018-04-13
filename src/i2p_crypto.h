#ifndef I2P_CRYPTO_H
#define I2P_CRYPTO_H
#include "common.h"

struct i2p_eddsa
{
  uint8_t priv[64];
  uint8_t pub[32];
};

struct i2p_elg
{
  uint8_t priv[256];
  uint8_t pub[256];
};


struct i2p_signer;

struct i2p_privkeybuf
{
  // eddsa signing keypair
  struct i2p_eddsa eddsa;
  // elgamal encryption keypair
  struct i2p_elg elg;
  // signing context
  struct i2p_signer * signer;
};

void i2p_signer_free(struct i2p_signer * signer);

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

void i2p_crypto_init(void);
void i2p_crypto_end(void);

bool i2p_dest_load(struct i2p_dest * dest, uint8_t * data, size_t len);

void i2p_keygen(struct i2p_privkeybuf * priv);

void i2p_elg_keygen(uint8_t * priv, uint8_t * pub);

void i2p_privkey_dest(struct i2p_privkeybuf * priv, struct i2p_dest * pub);

void i2p_dest_tob32addr(struct i2p_dest * dest, char * buf, size_t sz);

size_t i2p_dest_sigsize(struct i2p_privkeybuf * priv);

void i2p_dest_sign(struct i2p_privkeybuf * priv, const uint8_t * buf, size_t sz, uint8_t * sig);

#endif
