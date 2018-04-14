#ifndef DNS_H
#define DNS_H
#include "common.h"

struct dns_param
{
  char addr[256];
  int port;
};

struct dns_state;

void dns_state_add_mapping(struct dns_state * st, const char * name, struct in_addr addr);

void dns_state_init(struct dns_state * st);

void dns_state_process_data(struct dns_state * st, uint8_t * data, size_t sz);

#endif
