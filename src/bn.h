#ifndef BN_H
#define BN_H
#include "common.h"
#include <openssl/bn.h>

bool bn2buf (const BIGNUM * bn, uint8_t * buf, size_t len);

#endif
