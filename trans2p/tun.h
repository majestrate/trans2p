#ifndef TUN_H
#define TUN_H
#include "ringbuf.h"
#include "evloop.h"
#include "i2cp.h"
#include "packet.h"

struct tunif
{
  int fd;
  struct ev_event ev;
  struct ringbuf read;
  struct ringbuf write;
};

static inline void tunif_init(struct tunif * t, int fd)
{
  t->fd = fd;
  ringbuf_init(&t->read);
  ringbuf_init(&t->write);
}

void tunif_tick(struct tunif * t, struct i2cp_state * i, struct packet_state * pkt);

#endif
