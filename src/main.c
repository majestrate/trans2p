/**
   trans2p main
 */
#include "evloop.h"
#include "blocking.h"
#include <assert.h>


struct trans2p
{
  struct ev_impl * impl;
  struct ev_api api;
  int i2cp_fd;
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
  struct trans2p t;
  struct ev_api * api;
  struct ev_event ev;
  assert(ev_init(&t.api));
  t.running = true;
  api = &t.api;
  t.impl = api->open();
  assert(t.impl);
  while(t.running)
  {
    if(blocking_tcp_connect(i2cp_addr, i2cp_port, &t.i2cp_fd))
    {
      ev.fd = t.i2cp_fd;
      ev.ptr = 0;
      ev.flags = (EV_READ | EV_WRITE);
      assert(api->add(t.impl, &ev));
      mainloop(&t);
      api->del(t.impl, t.i2cp_fd);
    }
  }
  api->close(t.impl);
}
