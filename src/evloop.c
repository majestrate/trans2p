#include "evloop.h"
#ifdef _USE_EPOLL
#include "impl_epoll.h"
#endif
#ifdef _USE_KQUEUE
#include "impl_kqueue.h"
#endif

#include <string.h>

bool ev_init(struct ev_api * api)
{
  memset(api, 0, sizeof(struct ev_api));
#ifdef _USE_EPOLL
  api->open = ev_epoll_open;
  api->close = ev_epoll_close;
  api->add = ev_epoll_add;
  api->del = ev_epoll_del;
  api->poll = ev_epoll_poll;
  return true;
#else  
#ifdef _USE_KQUEUE
  api->open = ev_kqueue_open;
  api->close = ev_kqueue_close;
  api->add = ev_kqueue_add;
  api->del = ev_kqueue_del;
  api->poll = ev_kqueue_poll;
  return true;
#else
  return false;
#endif
#endif
}
