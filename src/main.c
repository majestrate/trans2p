/**
   trans2p main
 */
#include "evloop.h"
#include "blocking.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>

struct trans2p
{
  struct ev_impl * impl;
  struct ev_api api;
  int i2cp_fd;
  int tunfd;
  bool running;
};


void mainloop(struct trans2p * t)
{
  struct ev_api * api = &t->api;
  struct ev_impl * impl = t->impl;
  struct ev_event ev;
  int res;
  do
  {
    res = api->poll(impl, 10, &ev);
  }
  while(res != -1);
}

int main(int argc, char * argv[])
{
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
  
  struct trans2p t;
  struct ev_api * api;
  struct ev_event ev;
  assert(ev_init(&t.api));
  t.running = true;
  api = &t.api;
  t.impl = api->open();
  assert(t.impl);
  struct tun_param tun;
  tun.ifname = argv[3];
  tun.mtu = 1500;
  assert(inet_pton(AF_INET, "10.55.0.1", &tun.addr) == 1);
  assert(inet_pton(AF_INET, "255.255.255.0", &tun.netmask) == 1);
  printf("open tun interface %s\n", tun.ifname);
  t.tunfd = api->tun(t.impl, tun);
  if(t.tunfd == -1) return 1;
  while(t.running)
  {
    printf("connecting to %s port %d\n", i2cp_addr, i2cp_port);
    if(blocking_tcp_connect(i2cp_addr, i2cp_port, &t.i2cp_fd))
    {
      ev.fd = t.i2cp_fd;
      ev.ptr = 0;
      ev.flags = (EV_READ | EV_WRITE);
      assert(api->add(t.impl, &ev));
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
