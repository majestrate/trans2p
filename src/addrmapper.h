#ifndef ADDRMAPPER_H
#define ADDRMAPPER_H
#include "common.h"

struct addr_mapper;

void addr_mapper_init(struct addr_mapper * m, struct in_addr baseaddr, struct in_addr netmask);

#endif
