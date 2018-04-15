#include "addrmapper_internal.h"

void addr_mapper_init(struct addr_mapper * m, struct in_addr baseaddr, struct in_addr netmask)
{
  memcpy(&m->baseaddr, &baseaddr, sizeof(struct in_addr));
  memcpy(&m->netmask, &netmask, sizeof(struct in_addr));
  memcpy(&m->curaddr, &baseaddr, sizeof(struct in_addr));
  m->curaddr.s_addr += 1;
}
