#ifndef TUN_H
#define TUN_H
#include "ringbuf.h"
#include "evloop.h"
#include "i2cp.h"
#include "packet.h"

struct tunif
{
  struct ev_event ev;
  struct ringbuf read;
  struct ringbuf write;
};

static inline void tunif_init(struct tunif * t, int fd)
{
  t->ev.fd = fd;
  t->ev.flags = EV_READ | EV_WRITE;
  ringbuf_init(&t->read);
  ringbuf_init(&t->write);
}

void tunif_tick(struct tunif * t, struct i2cp_state * i, struct packet_state * pkt);

#endif
