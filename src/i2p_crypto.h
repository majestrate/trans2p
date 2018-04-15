#ifndef I2P_CRYPTO_H
#define I2P_CRYPTO_H
#include "common.h"
#include "dsa.h"
#include "elg.h"
#include "eddsa.h"

struct i2p_privkeybuf;

struct i2p_certbuf;

struct i2p_dest;

void i2p_crypto_init(void);
void i2p_crypto_end(void);

bool i2p_dest_load(struct i2p_dest * dest, uint8_t * data, size_t len);

void i2p_keygen(struct i2p_privkeybuf * priv);

void i2p_privkey_dest(struct i2p_privkeybuf * priv, struct i2p_dest * pub);

void i2p_dest_tob32addr(struct i2p_dest * dest, char * buf, size_t sz);

size_t i2p_dest_sigsize(struct i2p_privkeybuf * priv);

bool i2p_dest_sign(struct i2p_privkeybuf * priv, const uint8_t * buf, size_t sz, uint8_t * sig);

bool i2p_dest_verify(struct i2p_dest * dest, const uint8_t * buf, size_t sz, const uint8_t * sig);

#endif
