#ifndef DNS_H
#define DNS_H
#include "common.h"

struct dns_state;

void dns_state_add_mapping(struct dns_state * st, const char * name, struct in_addr addr);

#endif
