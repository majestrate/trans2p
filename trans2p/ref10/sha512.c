#include "crypto_hash_sha512.h"
#include <openssl/sha.h>


void crypto_hash_sha512(unsigned char * dst, const unsigned char * src, size_t sz)
{
  SHA512(src, sz, dst);
}
