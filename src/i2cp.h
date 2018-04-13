#ifndef I2CP_H
#define I2CP_H
#include "common.h"
#include "i2p_crypto.h"
#include <zlib.h>

struct i2cp_state;


typedef void (*i2cp_write_handler)(void *, uint8_t *, uint32_t);

typedef void (*i2cp_msg_handlerfunc)(uint8_t *, uint32_t, struct i2cp_state *, void *);

void i2cp_set_msghandler(struct i2cp_state * st, uint8_t msgtype, i2cp_msg_handlerfunc h, void * user);

void i2cp_queue_send(struct i2cp_state * st, uint8_t msgtype, uint8_t * ptr, uint32_t sz);

void i2cp_flush_write(struct i2cp_state * state);
void i2cp_flush_read(struct i2cp_state * state);

void i2cp_offer(struct i2cp_state * state, uint8_t * data , ssize_t sz);

void i2cp_begin(struct i2cp_state * state);

void i2cp_tick(struct i2cp_state * state);


struct i2cp_payload
{
  z_stream gzip;
  uint8_t payload[65536];
  size_t sz;
  uint8_t proto;
  uint16_t srcport;
  uint16_t dstport;
  uint8_t * ptr;
  uint32_t ptrlen;
};

bool i2cp_parse_payload(struct i2cp_payload * p);

void i2cp_send_payload(struct i2cp_state * st, struct i2p_dest * to, struct i2cp_payload * p);

#endif
