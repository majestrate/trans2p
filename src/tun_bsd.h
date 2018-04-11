#ifndef TUN_BSD_H
#define TUN_BSD_H
#include "evloop.h"

int ev_bsd_opentun(struct ev_impl * impl, struct tun_param param);

#endif
