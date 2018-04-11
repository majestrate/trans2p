#ifndef TUN_WIN32_H
#define TUN_WIN32_H
#include "evloop.h"

int ev_win32_opentun(struct ev_impl * impl, struct tun_param param);

#endif
