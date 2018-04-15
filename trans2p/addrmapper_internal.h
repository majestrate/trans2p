#ifndef ADDRMAPPER_INTERNAL_H
#define ADDRMAPPER_INTERNAL_H
#include "addrmapper.h"

struct addr_mapper
{
  struct in_addr curaddr;
  struct in_addr netmask;
  struct in_addr baseaddr;
};

#endif
