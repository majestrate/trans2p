#ifndef PACKET_INTERNAL_H
#define PACKET_INTERNAL_H
#include "packet.h"
#include "dns_internal.h"

struct packet_state
{
  struct dns_state dns;
};

#endif
