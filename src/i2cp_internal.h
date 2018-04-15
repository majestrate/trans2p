#ifndef I2CP_INTERNAL_H
#define I2CP_INTERNAL_H
#include "i2cp.h"

typedef void (*i2cp_buffer_visitor)(uint8_t *, uint32_t, struct i2cp_state *);

struct i2cp_msgbuf
{
  uint32_t sz;
  uint8_t buf[65536];
};

struct i2cp_stringbuf
{
  uint8_t data[256];
};

#define RINGBUF_SZ (32)

struct i2cp_ringbuf
{
  uint16_t sz;
  uint16_t idx;
  struct i2cp_msgbuf buffs[RINGBUF_SZ];
};

struct i2cp_msg_handler
{
  i2cp_msg_handlerfunc func;
  void * ptr;
};

struct i2cp_state
{
  bool sentinit;
  uint16_t sid;
  void * writeimpl;
  struct i2cp_msg_handler handlers[256];
  i2cp_write_handler write;
  struct i2cp_msgbuf readcur;
  struct i2cp_ringbuf readbuf;
  struct i2cp_ringbuf writebuf;
};

void i2cp_state_init(struct i2cp_state * st, i2cp_write_handler h, void * impl);

#endif
