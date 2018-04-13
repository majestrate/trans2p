#include "i2pd/crypto.hpp"
#include "i2pd/signature.hpp"
#include <cassert>

const size_t NIST_256_PADDING_BYTES = 64;
const size_t NIST_384_PADDING_BYTES = 32;
const size_t EDDSA_PADDING_BYTES = 96;

const uint8_t CERT_NULL = 0;
const uint8_t CERT_KEYCERT = 5;

const uint16_t DSA_KEYTYPE = 0;
const uint16_t EDDSA_KEYTYPE = 7;
const uint16_t ELG_KEYTYPE = 0;


extern "C" {

#include "i2p_crypto.h"
#include "i2p_endian.h"

struct i2p_signer
{
  i2p::crypto::Signer * impl;
};
  
bool i2p_dest_load(struct i2p_dest * dest, uint8_t * data, size_t sz)
{
  uint8_t * ptr = dest->buf;
  memcpy(ptr, data, sz);
  dest->sz = sz;
  dest->enckey = ptr;
  ptr += 256 + 128;
  if(*ptr == CERT_KEYCERT)
  {
    dest->cert.type = CERT_KEYCERT;
    ptr ++;
    dest->cert.sz = bufbe16toh(ptr);
    ptr += 2;
    dest->sigtype = bufbe16toh(ptr);
    ptr += 2;
    dest->enctype = bufbe16toh(ptr);
    if(dest->sigtype == EDDSA_KEYTYPE)
    {
      dest->sigkey = dest->buf + 256 + EDDSA_PADDING_BYTES;
      return true;
    }
  }
  else if(*ptr == CERT_NULL)
  {
    dest->sigtype = DSA_KEYTYPE;
    dest->enctype = ELG_KEYTYPE;
    dest->sigkey = dest->buf + 256;
    dest->cert.type = CERT_NULL;
    dest->cert.sz = 0;
    dest->cert.data = nullptr;
    return true;
  }
  return false;
}

  void i2p_signer_free(struct i2p_signer * signer)
  {
    delete signer->impl;
    delete signer;
  }

    
void i2p_elg_keygen(uint8_t * priv, uint8_t * pub)
{
  i2p::crypto::GenerateElGamalKeyPair(priv, pub);
}
  
void i2p_keygen(struct i2p_privkeybuf * priv)
{
  i2p::crypto::CreateEDDSA25519RandomKeys(priv->eddsa.priv, priv->eddsa.pub);
  i2p_elg_keygen(priv->elg.priv, priv->elg.pub);
  priv->signer = new i2p_signer{new i2p::crypto::EDDSA25519Signer(priv->eddsa.priv, priv->eddsa.pub)};
}

void i2p_privkey_dest(struct i2p_privkeybuf * priv, struct i2p_dest * pub)
{
  uint8_t * ptr = pub->buf;
  pub->enckey = ptr;
  memcpy(pub->enckey, priv->elg.pub, 256);
  ptr += 256;
  RAND_bytes(ptr, EDDSA_PADDING_BYTES);
  ptr += EDDSA_PADDING_BYTES;
  pub->sigkey = ptr;
  memcpy(pub->sigkey, priv->eddsa.pub, 32);
  ptr += 32;

  pub->cert.type = CERT_KEYCERT;
  pub->cert.sz = 4;

  *ptr = pub->cert.type;
  ptr ++;
  htobe16buf(ptr, pub->cert.sz);
  ptr += 2;
  pub->cert.data = ptr;

  htobe16buf(ptr, EDDSA_KEYTYPE);
  ptr += 2;
  htobe16buf(ptr, ELG_KEYTYPE);
  ptr += 2;
  
  pub->sz = ptr - pub->buf;
}

void i2p_dest_tob32addr(struct i2p_dest * dest, char * buf, size_t sz)
{
  assert(dest->sz <= sizeof(dest->buf));
  size_t len;
  uint8_t digest[32];
  SHA256(dest->buf, dest->sz, digest);
  len = i2p::data::ByteStreamToBase32(digest, 32, buf, sz);
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

  size_t i2p_dest_sigsize(struct i2p_privkeybuf * priv)
  {
    return priv->signer->impl->GetSignatureLen();
  }

  void i2p_dest_sign(struct i2p_privkeybuf * priv, const uint8_t * buf, size_t sz, uint8_t * sig)
  {
    priv->signer->impl->Sign(buf, sz, sig);
  }
  
}
