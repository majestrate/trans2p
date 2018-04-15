#include "eddsa_internal.h"
#include <assert.h>

bool i2p_eddsa_sign(struct i2p_eddsa * ed, const uint8_t * buf, size_t sz, uint8_t * sig)
{
  ed25519_sign(sig, buf, sz, ed->pub, ed->priv);
  return true;
}

bool i2p_eddsa_verify(const uint8_t * pubkey, const uint8_t * buf, size_t sz, const uint8_t * sig)
{
  return ed25519_verify(sig, buf, sz, pubkey) == 1;
}

void i2p_eddsa_keygen(struct i2p_eddsa * ed)
{
  assert(ed25519_create_keypair(ed->priv, ed->pub) != 0);
}
