
#include "i2p_crypto_internal.h"
#include "elg.h"
#include "i2p_endian.h"
#include "base.h"
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include <assert.h>

#define NIST_256_PADDING_BYTES (64)
#define NIST_384_PADDING_BYTES (32)
#define EDDSA_PADDING_BYTES (96)
#define CERT_NULL (0)
#define CERT_KEYCERT (5)

#define DSA_KEYTYPE  (0)
#define EDDSA_KEYTYPE (7)
#define ELG_KEYTYPE (0)

void i2p_crypto_init(void)
{
  SSL_library_init();
}

void i2p_crypto_end(void)
{
}
  
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
    dest->cert.data = 0;
    return true;
  }
  return false;
}
  
void i2p_keygen(struct i2p_privkeybuf * priv)
{
  i2p_eddsa_keygen(&priv->eddsa);
  i2p_elg_keygen(&priv->elg);
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
  len = ByteStreamToBase32(digest, 32, buf, sz);
  memcpy(buf + len, ".b32.i2p", 10);
}


size_t i2p_dest_sigsize(struct i2p_privkeybuf * priv)
{
  switch(priv->sigtype)
  {
  case EDDSA_KEYTYPE:
    return 32;
  case DSA_KEYTYPE:
    return 128;
  default:
    return 0;
  }
}

bool i2p_dest_sign(struct i2p_privkeybuf * priv, const uint8_t * buf, size_t sz, uint8_t * sig)
{
  switch(priv->sigtype)
  {
  case EDDSA_KEYTYPE:
    return i2p_eddsa_sign(&priv->eddsa, buf, sz, sig);
  case DSA_KEYTYPE:
    return i2p_dsa_sign(&priv->dsa, buf, sz, sig);
  default:
    return false;
  }
}

bool i2p_dest_verify(struct i2p_dest * dest, const uint8_t * buf, size_t sz, const uint8_t * sig)
{
  switch(dest->sigtype)
  {
  case EDDSA_KEYTYPE:
    return i2p_eddsa_verify(dest->sigkey, buf, sz, sig);
  case DSA_KEYTYPE:
    return i2p_dsa_verify(dest->sigkey, buf, sz, sig);
  default:
    return false;
  }
}

