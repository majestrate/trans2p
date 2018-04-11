#ifndef BLOCKING_H
#define BLOCKING_H
#include "common.h"

bool blocking_tcp_connect(const char * host, int port, int * fd);

#endif
