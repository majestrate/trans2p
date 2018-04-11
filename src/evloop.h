#ifndef EVLOOP_H
#define EVLOOP_H
#include "common.h"

#define EV_READ (1 << 0)
#define EV_WRITE (1 << 1)

struct ev_event
{
  int fd;
  void * ptr;
  int flags;
};

struct ev_impl;

struct tun_param
{
  const char * ifname;
  int mtu;
  struct in_addr addr;
  struct in_addr netmask;
};

struct ev_api
{
  struct ev_impl * (*open)(void);
  void (*close)(struct ev_impl *);
  bool (*add)(struct ev_impl *, struct ev_event *);
  void (*del)(struct ev_impl *, int);
  int (*poll)(struct ev_impl *, uint32_t, struct ev_event *);
  int (*tun)(struct ev_impl *, struct tun_param);
};

bool ev_init(struct ev_api * api);


#endif
