#ifndef ADDRMAPPER_H
#define ADDRMAPPER_H
#include "common.h"

struct addr_mapper;

void addr_mapper_init(struct addr_mapper * m, struct in_addr * baseaddr, struct in_addr * netmask);

/**
   get next address, increment addr_mapper next address
 */
void addr_mapper_nextaddr(struct addr_mapper * m, struct in_addr * nextaddr);

/**
   return true if next address is in range and peek address into nextaddr
   return false if next address is not in range and nextaddr is not modified
 */
bool addr_mapper_peekaddr(struct addr_mapper * m, struct in_addr * nextaddr);

#endif
