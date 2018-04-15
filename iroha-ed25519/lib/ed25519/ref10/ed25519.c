#include <ed25519/ed25519/crypto_verify.h>
#include <ed25519/ed25519.h>
#include <string.h>
#include "ge.h"
#include "sc.h"

int ed25519_create_keypair(unsigned char *sk, unsigned char *pk) {
  if (!randombytes(sk, ed25519_privkey_SIZE))
    return ED25519_ERROR;            /* RNG failed, not enough entropy */
  ed25519_derive_public_key(sk, pk); /* fill with data */
  return ED25519_SUCCESS;            /* ok */
}

void ed25519_derive_public_key(const unsigned char *sk, unsigned char *pk) {
  unsigned char az[64];
  ge_p3 A;

  sha512(az, sk, 32);
  az[0] &= 248;
  az[31] &= 63;
  az[31] |= 64;

  ge_scalarmult_base(&A, az);
  ge_p3_tobytes(pk, &A);
}

void ed25519_sign(unsigned char *sig, const unsigned char *msg,
                  unsigned long long msglen, const unsigned char *pk,
                  const unsigned char *sk) {
  unsigned char context[SHA_512_CONTEXT_SIZE];
  unsigned char az[64];
  unsigned char nonce[64];  // r
  unsigned char hram[64];
  ge_p3 R;

  sha512_init((void *)context);
  sha512_update((void *)context, sk, ed25519_privkey_SIZE);
  sha512_final((void *)context, az);
  az[0] &= 248;
  az[31] &= 63;
  az[31] |= 64;
  /* az: 64-byte H(sk) */
  /* az: 32-byte scalar a, 32-byte randomizer z */

  sha512_init((void *)context);
  sha512_update((void *)context, /* z */ az + 32, 32);
  sha512_update((void *)context, msg, msglen);
  sha512_final((void *)context, nonce);
  /* nonce: 64-byte H(z,msg) */

  sc_reduce(nonce);
  ge_scalarmult_base(&R, nonce);
  ge_p3_tobytes(sig, &R);
  /* sig: [32 bytes R | 32 bytes uninit] */

  sha512_init((void *)context);
  // first 32 bytes of signature
  sha512_update((void *)context, /* R */ sig, 32);
  sha512_update((void *)context, /* A */ pk, ed25519_pubkey_SIZE);
  sha512_update((void *)context, msg, msglen);
  sha512_final((void *)context, hram);
  /* hram: 64-byte H(R,A,m) */

  sc_reduce(hram);
  sc_muladd(sig + 32, hram, az, nonce);
  /* sig: [32 bytes R | 32 bytes S] */
}

int ed25519_verify(const unsigned char *sig, const unsigned char *msg,
                   unsigned long long msglen, const unsigned char *pk) {
  unsigned char context[SHA_512_CONTEXT_SIZE];
  unsigned char pkcopy[32];
  unsigned char rcopy[32];
  unsigned char hram[64];
  unsigned char rcheck[32];
  ge_p3 A;
  ge_p2 R;

  if (sig[63] & 224) goto badsig;
  if (ge_frombytes_negate_vartime(&A, pk) != 0) goto badsig;

  memcpy(pkcopy, pk, 32);
  memcpy(rcopy, /* R, first 32 bytes */ sig, 32);

  sha512_init((void *)context);
  // first 32 bytes of signature
  sha512_update((void *)context, /* R */ sig, 32);
  sha512_update((void *)context, /* A */ pk, ed25519_pubkey_SIZE);
  sha512_update((void *)context, msg, msglen);
  sha512_final((void *)context, hram);
  /* scs: S = nonce + H(R,A,m)a */

  sc_reduce(hram);
  ge_double_scalarmult_vartime(&R, hram, &A, /* S */ sig + 32);
  ge_tobytes(rcheck, &R);

  if (crypto_verify_32(rcopy, rcheck) == 0) {
    return ED25519_SIGNATURE_VALID;
  }

badsig:
  return ED25519_SIGNATURE_INVALID;
}
