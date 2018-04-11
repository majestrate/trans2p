/**
   trans2p main
 */
#include "evloop.h"
#include "blocking.h"
#include "i2cp.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>

struct trans2p
{
  struct ev_impl * impl;
  struct ev_api api;
  struct ev_event i2cp_ev;
  struct ev_event tun_ev;
  struct i2cp_state * i2cp;
  int i2cp_fd;
  int tunfd;
  bool running;
};

struct handler
{
  struct trans2p * t;

  uint8_t * buf;
  
  void (*handle)(ssize_t, struct handler *);
};

void tun_onpacket(ssize_t sz, struct handler * h)
{
  if(sz > 0)
  {
    uint8_t * pkt = h->buf;
  }
}

void i2cp_onread(ssize_t sz, struct handler * h)
{
  if(sz > 0)
  {
    i2cp_offer(h->t->i2cp, h->buf, sz);
  }
}


static void i2cp_write(void * impl, uint8_t * ptr, uint32_t sz)
{
  struct trans2p * t = (struct trans2p * ) impl;
  int res = write(t->i2cp_fd, ptr, sz);
  if (res == -1) perror("i2cp_write()");
}

void mainloop(struct trans2p * t)
{
  struct ev_api * api = &t->api;
  struct ev_impl * impl = t->impl;
  struct ev_event ev;
  struct handler * h;
  int res;
  ssize_t count;
  do
  {
    res = api->poll(impl, 10, &ev);
    if(res == 0)
      i2cp_tick(t->i2cp);
    else
    {
      h = (struct handler *) ev.ptr;
      if(ev.flags & EV_READ)
      {
        do
        {
          count = read(ev.fd, h->buf, 512);
          if(count > 0)
          {
            h->handle(count, h);
          }
          else if (count == 0)
          {
          // connection closed
            close(ev.fd);
            api->del(impl, ev.fd);
          }
          else if (errno != EAGAIN)
          {
            perror("read");
          }
        }
        while(count > 0);     
      }
    }
  }
  while(res != -1);
}

int main(int argc, char * argv[])
{
  
  struct trans2p t;

  uint8_t buf[65536];
  
  struct handler tun_handler = {
    .t = &t,
    .buf = buf,
    .handle = &tun_onpacket
  };
  
  struct handler i2cp_handler = {
    .t = &t,
    .buf = buf,
    .handle = &i2cp_onread,
  };
  
  const char * i2cp_addr;
  int i2cp_port;

  if(argc != 4)
  {
    printf("usage %s i2cp_host i2cp_port ifname\n", argv[0]);
    return 1;
  }
  i2cp_addr = argv[1];
  i2cp_port = atoi(argv[2]);
  if(i2cp_port == -1)
  {
    printf("invalid i2cp port %s\n", argv[2]);
    return 1;
  }
  t.i2cp = i2cp_state_new(&i2cp_write, &t);
  assert(t.i2cp);
  struct ev_api * api;
  assert(ev_init(&t.api));
  t.running = true;
  api = &t.api;
  t.impl = api->open();
  assert(t.impl);
  /*
  struct tun_param tun;
  tun.ifname = argv[3];
  tun.mtu = 1500;
  assert(inet_pton(AF_INET, "10.55.0.1", &tun.addr) == 1);
  assert(inet_pton(AF_INET, "255.255.255.0", &tun.netmask) == 1);
  printf("open tun interface %s\n", tun.ifname);
  t.tunfd = api->tun(t.impl, tun);
  if(t.tunfd == -1) return 1;
  t.tun_ev.fd = t.tunfd;
  t.tun_ev.ptr = &tun_handler;
  t.tun_ev.flags = EV_READ;
  */
  while(t.running)
  {
    printf("connecting to %s port %d\n", i2cp_addr, i2cp_port);
    if(blocking_tcp_connect(i2cp_addr, i2cp_port, &t.i2cp_fd))
    {
      printf("connected\n");
      t.i2cp_ev.fd = t.i2cp_fd;
      t.i2cp_ev.ptr = &i2cp_handler;
      t.i2cp_ev.flags = EV_READ;
      assert(api->add(t.impl, &t.i2cp_ev));
      mainloop(&t);
      api->del(t.impl, t.i2cp_fd);
    }
    else
    {
      perror("blocking_tcp_connect()");
      sleep(1);
    }
  }
  api->close(t.impl);
}
