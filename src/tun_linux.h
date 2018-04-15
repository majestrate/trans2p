#ifndef TUN_LINUX_H
#define TUN_LINUX_H
#include "evloop.h"

int ev_linux_opentun(struct ev_impl * impl, struct tun_param param);

#endif
