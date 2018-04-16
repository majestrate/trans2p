#include "addrmapper_internal.h"

void addr_mapper_init(struct addr_mapper * m, struct in_addr * baseaddr, struct in_addr * netmask)
{
  memcpy(&m->baseaddr, baseaddr, sizeof(struct in_addr));
  memcpy(&m->netmask, netmask, sizeof(struct in_addr));
  memcpy(&m->curaddr, baseaddr, sizeof(struct in_addr));
}

static inline bool addr_in_range(struct in_addr addr, struct in_addr base, struct in_addr netmask)
{
  return (addr.s_addr & netmask.s_addr) == (base.s_addr & netmask.s_addr);
}

void addr_mapper_nextaddr(struct addr_mapper * m, struct in_addr * nextaddr)
{
  m->curaddr.s_addr += 1;
  if(!addr_in_range(m->curaddr, m->baseaddr, m->netmask))
  {
    m->curaddr.s_addr = m->baseaddr.s_addr + 1;
  }
  nextaddr->s_addr = m->curaddr.s_addr;
}

bool addr_mapper_peekaddr(struct addr_mapper * m, struct in_addr * nextaddr)
{
  struct in_addr addr;
  addr.s_addr = m->curaddr.s_addr + 1;
  if (addr_in_range(addr, m->baseaddr, m->netmask))
  {
    nextaddr->s_addr = addr.s_addr;
    return true;
  }
  return false;
}
