#include "bn.h"

bool bn2buf (const BIGNUM * bn, uint8_t * buf, size_t len)
{
  int offset = len - BN_num_bytes (bn);
  if (offset < 0) return false;
  BN_bn2bin (bn, buf + offset);
  memset (buf, 0, offset);
  return true;
}
