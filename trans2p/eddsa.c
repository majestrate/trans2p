#include "eddsa_internal.h"
#include <assert.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include "ref10/crypto_verify_32.h"
#include "ref10/ge.h"
#include "ref10/sc.h"

bool i2p_eddsa_sign(struct i2p_eddsa * ed, const uint8_t * buf, size_t sz, uint8_t * sigbuf)
{
  uint8_t hram[64];
  uint8_t nonce[64];
  uint8_t az[64];
  uint8_t sig[64];
  ge_p3 R;

  SHA512_CTX ctx;
  SHA512_Init (&ctx);
  SHA512_Update (&ctx, ed->key, 32);
  SHA512_Final (az, &ctx);
  az[0] &= 248;
  az[31] &= 63;
  az[31] |= 64;

  SHA512_Init(&ctx);
  SHA512_Update(&ctx, az + 32, 32);
  SHA512_Update(&ctx, buf, sz);
  SHA512_Final(nonce, &ctx);
  
  sc_reduce(nonce);
  ge_scalarmult_base(&R, nonce);
  ge_p3_tobytes(sig,&R);

  SHA512_Init(&ctx);
  SHA512_Update(&ctx, sig, 32);
  SHA512_Update(&ctx, ed->key + 32, 32);
  SHA512_Update(&ctx, buf, sz);
  SHA512_Final(hram, &ctx);

  sc_reduce(hram);
  sc_muladd(sig+32, hram, az, nonce);
  memcpy(sigbuf, sig, 64);
  return true;
}

bool i2p_eddsa_verify(const uint8_t * pubkey, const uint8_t * buf, size_t sz, const uint8_t * sig) {

  unsigned char h[64];
  unsigned char rcheck[32];
  ge_p3 A;
  ge_p2 R;
  SHA512_CTX sha;
  SHA512_Init(&sha);

  if (ge_frombytes_negate_vartime(&A,pubkey) != 0)
  {
    return false;
  }
 
  SHA512_Update(&sha,sig,32);
  SHA512_Update(&sha,pubkey, 32);
  SHA512_Update(&sha,buf,sz);
  SHA512_Final(h, &sha);
  sc_reduce(h);

  ge_double_scalarmult_vartime(&R,h,&A,sig + 32);
  ge_tobytes(rcheck,&R);
  return crypto_verify_32(rcheck, sig) == 0;
}

void i2p_eddsa_keygen(struct i2p_eddsa * ed)
{
  uint8_t az[64];
  ge_p3 A;

  RAND_bytes(ed->key,32);
  SHA512(ed->key,32,az);
  az[0] &= 0xf8;
  az[31] &= 0x3f;
  az[31] |= 0x40;

  ge_scalarmult_base(&A,az);
  ge_p3_tobytes(ed->key + 32,&A);
}
