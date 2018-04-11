#ifndef IMPL_EPOLL_H
#define IMPL_EPOLL_H
#include "evloop.h"

struct ev_impl;

struct ev_impl * ev_epoll_open(void);
void ev_epoll_close(struct ev_impl * impl);
bool ev_epoll_add(struct ev_impl * impl, struct ev_event * ev);
void ev_epoll_del(struct ev_impl * impl, int fd);
int ev_epoll_poll(struct ev_impl * impl, uint32_t ms, struct ev_event * ev);

#endif

