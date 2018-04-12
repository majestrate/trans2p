#include "evloop_epoll.h"
#include <sys/epoll.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

struct ev_impl
{
  int epollfd;
};

struct ev_impl * ev_epoll_open(void)
{
  struct ev_impl * impl = malloc(sizeof(struct ev_impl));
  impl->epollfd = epoll_create(128);
  if(impl->epollfd == -1)
    perror("epoll_create()");
  else
    return impl;
  free(impl);
  return NULL;
};

void ev_epoll_close(struct ev_impl * impl)
{
  close(impl->epollfd);
  free(impl);
}

bool ev_epoll_add(struct ev_impl * impl, struct ev_event * ev)
{
  struct epoll_event epev;
  epev.data.ptr = ev;
  epev.events = 0;
  if(ev->flags & EV_READ)
    epev.events |= EPOLLIN;
  if(ev->flags & EV_WRITE)
    epev.events |= EPOLLOUT;
  return epoll_ctl(impl->epollfd, EPOLL_CTL_ADD, ev->fd, &epev) != 1;
}

void ev_epoll_del(struct ev_impl * impl, int fd)
{
  epoll_ctl(impl->epollfd, EPOLL_CTL_DEL, fd, NULL);
}

int ev_epoll_poll(struct ev_impl * impl, uint32_t ms, struct ev_event * ev)
{
  struct epoll_event epv;
  struct ev_event * event;
  int res;
  res = epoll_wait(impl->epollfd, &epv, 1, ms);
  if(res > 0)
  {
    event = (struct ev_event *) epv.data.ptr;
    ev->fd = event->fd;
    ev->ptr = event->ptr;
  }
  return res;
}
