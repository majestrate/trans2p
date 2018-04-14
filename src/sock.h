#ifndef SOCK_H
#define SOCK_H
#include "common.h"

int udp_socket();

bool udp_bind(int fd, const char * addr, int port);

#endif
