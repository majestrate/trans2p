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

struct i2cp_stringbuf
{
  uint8_t data[256];
};

#define RINGBUF_SZ (128)

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
  void * writeimpl;
  struct i2cp_msg_handler handlers[256];
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

bool i2cp_get_handler(struct i2cp_state * st, uint8_t msgno, struct i2cp_msg_handler ** handler)
{
  *handler = NULL;
  if(st->handlers[msgno].func)
  {
    *handler = &st->handlers[msgno];
  }
  return *handler != NULL;
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
  st->write(st->writeimpl, ptr, sz);
}

void i2cp_putstring(struct i2cp_stringbuf * buf, char * str)
{
  uint8_t * ptr = buf->data;
  size_t slen = strlen(str);
  if(slen > 255) slen = 255;
  ptr[0] = (uint8_t) slen;
  memcpy(ptr+1, str, slen);
}

static inline uint32_t i2cp_strlen(struct i2cp_stringbuf * buf)
{
  return buf->data[0];
}

void i2cp_set_msghandler(struct i2cp_state * st, uint8_t msgtype, i2cp_msg_handlerfunc h, void * user)
{
  st->handlers[msgtype].func = h;
  st->handlers[msgtype].ptr = user;
}

void i2cp_read_msg(uint8_t * ptr, uint32_t sz, struct i2cp_state * st)
{
  struct i2cp_msg_handler * handler;
  uint32_t msglen = 0;
  if(sz > 5)
  {
    msglen = bufbe32toh(ptr);
    if(msglen + 5 == sz)
    {
      if(i2cp_get_handler(st, ptr[4], &handler))
        handler->func(ptr + 5, msglen, st, handler->ptr);
      else
        printf("unhandled i2cp message: %i\n", ptr[4]);
    }
    else
      printf("i2cp message size missmatch: %d != %d", msglen + 5, sz);
  }
  else
    printf("i2cp message too small: %d", sz);
}

void i2cp_begin(struct i2cp_state * state)
{
  if(!state->sentinit)
  {
    // protocol byte
    uint8_t b = 0x2a;
    i2cp_write_msg(&b, 1, state);

    // get date messagee
    struct i2cp_stringbuf str;
    i2cp_putstring(&str, I2CP_VERSION);
    uint32_t sz = i2cp_strlen(&str);
    i2cp_queue_send(state, GETDATE, str.data, sz);
    i2cp_flush_write(state);
    state->sentinit = true;
  }
}

void i2cp_tick(struct i2cp_state * st)
{
  i2cp_flush_read(st);
  i2cp_flush_write(st);
}

void i2cp_queue_send(struct i2cp_state * st, uint8_t msgtype, uint8_t * ptr, uint32_t sz)
{
  i2cp_ringbuf_append(&st->writebuf, msgtype, ptr, sz);
}

void i2cp_flush_write(struct i2cp_state * st)
{
  i2cp_ringbuf_flush(&st->writebuf, i2cp_write_msg, st);
}

void i2cp_flush_read(struct i2cp_state * st)
{
  i2cp_ringbuf_flush(&st->readbuf, i2cp_read_msg, st);
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
  memset(st->handlers, 0, sizeof(st->handlers));
  return st;
}
