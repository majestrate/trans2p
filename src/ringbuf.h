#ifndef RINGBUF_H
#define RINGBUF_H

#include "common.h"
#include <string.h>

#define RINGBUF_BUFF_SZ (24)

struct ringbuf_msgbuf
{
  uint16_t sz;
  uint8_t buf[65536];
};

struct ringbuf
{
  uint16_t sz;
  uint16_t idx;
  struct ringbuf_msgbuf buffs[RINGBUF_BUFF_SZ];
};

typedef void (*ringbuf_visitor)(uint8_t *, uint16_t, void *);

static inline void ringbuf_init(struct ringbuf * b)
{
  b->sz = 0;
  b->idx = 0;
}

static inline bool ringbuf_append(struct ringbuf * b, uint8_t * ptr, uint16_t sz)
{
  struct ringbuf_msgbuf * m = &b->buffs[b->idx];
  if(b->sz < RINGBUF_BUFF_SZ)
  {
    b->sz ++;
    b->idx = (b->idx + 1) % RINGBUF_BUFF_SZ;
    m->sz = sz;
    memcpy(m->buf, ptr, sz);
  }
  return b->sz >= RINGBUF_BUFF_SZ;
}


static inline bool ringbuf_flush(struct ringbuf * b, ringbuf_visitor v, void * u)
{
  if(b->sz == 0) return false;
  struct ringbuf_msgbuf * msg;
  uint16_t sz = b->sz;
  uint16_t idx = b->idx;
  while(sz)
  {
    if(idx)
      idx = idx - 1;
    else
      idx = RINGBUF_BUFF_SZ - 1;
    sz--; 
  }
  while(b->sz)
  {
    msg = &b->buffs[idx];
    v(msg->buf, msg->sz, u);
    idx = (idx + 1) % RINGBUF_BUFF_SZ;
    b->sz --;
  }
  return true;
}

#endif
