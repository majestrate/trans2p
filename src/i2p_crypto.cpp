#include "i2pd/crypto.hpp"

extern "C" {

#include "i2p_crypto.h"


bool i2p_dest_load(struct i2p_dest * dest, uint8_t * data, size_t sz)
{
  return false;
}

void i2p_keygen(struct i2p_privkeybuf * priv)
{
}

void i2p_privkey_dest(struct i2p_privkeybuf * priv, struct i2p_dest * pub)
{
}

void i2p_dest_tob32addr(struct i2p_dest * dest, char * buf, size_t sz)
{
  size_t len;
  uint8_t digest[32];
  SHA256(dest->buf, dest->sz, digest);
  len =  i2p::data::ByteStreamToBase32(digest, 32, buf, sz);
  memcpy(buf + len, ".b32.i2p", 10);
}

  void i2p_crypto_init(void)
  {
    i2p::crypto::InitCrypto();
  }
  
  void i2p_crypto_end(void)
  {
    i2p::crypto::TerminateCrypto();
  }

}
