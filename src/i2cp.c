#include "i2cp.h"
#include "i2cp_msg.h"
#include "i2p_endian.h"
#include "version.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

typedef void (*i2cp_buffer_visitor)(uint8_t *, uint32_t, struct i2cp_state *);

struct i2cp_msgbuf
{
  uint32_t sz;
  uint8_t buf[65536];
};

#define RINGBUF_SZ (128)

struct i2cp_ringbuf
{
  uint16_t sz;
  uint16_t idx;
  struct i2cp_msgbuf buffs[RINGBUF_SZ];
};

struct i2cp_state
{
  bool sentinit;
  void * writeimpl;
  i2cp_write_handler write;
  struct i2cp_msgbuf readcur;
  struct i2cp_ringbuf readbuf;
  struct i2cp_ringbuf writebuf;
};

void i2cp_ringbuf_init(struct i2cp_ringbuf * b)
{
  b->sz = 0;
  b->idx = 0;
}

bool i2cp_ringbuf_append(struct i2cp_ringbuf * b, uint8_t t, uint8_t * ptr, uint32_t sz)
{
  struct i2cp_msgbuf * m = &b->buffs[b->idx];
  if(b->sz < RINGBUF_SZ)
  {
    b->sz ++;
    b->idx = (b->idx + 1) % RINGBUF_SZ;
    m->sz = sz;
    htobe32buf(m->buf, sz);
    m->buf[4] = t;
    memcpy(m->buf+5, ptr, sz);
  }
  return b->sz >= RINGBUF_SZ;
}

bool i2cp_ringbuf_flush(struct i2cp_ringbuf * b, i2cp_buffer_visitor v, struct i2cp_state * st)
{
  if(b->sz == 0) return false;
  struct i2cp_msgbuf * msg;
  uint16_t sz = b->sz;
  uint16_t idx = b->idx;
  while(sz)
  {
    if(idx)
      idx = idx - 1;
    else
      idx = RINGBUF_SZ - 1;
    sz--; 
  }
  while(b->sz)
  {
    msg = &b->buffs[idx];
    v(msg->buf, msg->sz, st);
    idx = (idx + 1) % RINGBUF_SZ;
    b->sz --;
  }
  return true;
}

void handle_i2cp_setdate(uint8_t * ptr, uint32_t len, struct i2cp_state * st)
{
  printf("got set date\n");
}

bool i2cp_get_handler(uint8_t msgno, i2cp_buffer_visitor * handler)
{
  switch(msgno)
  {
  case SETDATE:
    *handler = &handle_i2cp_setdate;
    return true;
  default:
    return false;
  }
}

void i2cp_offer(struct i2cp_state * state, uint8_t * data, ssize_t sz)
{
  if(sz <= 0) return;
 
  memcpy(state->readcur.buf + state->readcur.sz, data, sz);
  state->readcur.sz += sz;
  

  if(state->readcur.sz > 4)
  {
    uint32_t curlen = buf32toh(state->readcur.buf);
    if( curlen + 5 >= state->readcur.sz)
    {
      i2cp_ringbuf_append(&state->readbuf, state->readcur.buf[4], state->readcur.buf + 5, curlen);
      ssize_t diff = state->readcur.sz - (curlen + 5);
      state->readcur.sz = 0;
      i2cp_offer(state, state->readcur.buf + diff, diff);
    }
  }
}


void i2cp_write_msg(uint8_t * ptr, uint32_t sz, struct i2cp_state * st)
{
  assert(st);
  assert(st->write);
  assert(st->writeimpl);
  st->write(st->writeimpl, ptr, sz);
}

void i2cp_putstring(uint8_t **  msg, size_t sz, char * str)
{
  uint8_t * ptr = *msg;
  size_t s = strlen(str);
  if(s > 255) s = 255;
  if(s > sz) s = sz;
  ptr[0] = (uint8_t) s;
  memcpy(ptr+1, str, s);
  *msg = ptr + 1 + sz;
}

void i2cp_read_msg(uint8_t * ptr, uint32_t sz, struct i2cp_state * st)
{
  uint32_t msglen;
  if(sz > 5)
  {
    msglen = bufbe32toh(ptr);
    if(msglen + 5 == sz)
    {
      i2cp_buffer_visitor handler;
      if(i2cp_get_handler(ptr[4], &handler))
        handler(ptr + 5, msglen, st);
      else
        printf("unhandled i2cp message: %i\n", ptr[4]);
    }
    else
      printf("i2cp message size missmatch: %d != %d", msglen + 5, sz);
  }
  else
    printf("i2cp message too small: %d", sz);
}

void i2cp_tick(struct i2cp_state * state)
{
  assert(state);
  if(state->sentinit)
  {
    i2cp_ringbuf_flush(&state->readbuf, i2cp_read_msg, state);
    i2cp_ringbuf_flush(&state->writebuf, i2cp_write_msg, state);
  }
  else
  {
    uint8_t body[512];
    uint8_t * buf = body;
    uint16_t sz = 0;
    uint8_t b = 0x2a;
    i2cp_write_msg(&b, 1, state);
    state->sentinit = true;
   
    i2cp_putstring(&buf, sizeof(body), I2CP_VERSION);
    sz = buf - body;
    i2cp_ringbuf_append(&state->writebuf, GETDATE, body, sz);
    i2cp_ringbuf_flush(&state->writebuf, i2cp_write_msg, state);
  }
}

struct i2cp_state * i2cp_state_new(i2cp_write_handler h, void * impl)
{
  assert(h);
  assert(impl);
  struct i2cp_state * st = (struct i2cp_state *) malloc(sizeof(struct i2cp_state));
  if(!st) return NULL;
  st->write = h;
  st->sentinit = false;
  st->writeimpl = impl;
  st->readcur.sz = 0;
  i2cp_ringbuf_init(&st->readbuf);
  i2cp_ringbuf_init(&st->writebuf);
  return st;
}
