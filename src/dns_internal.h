#ifndef DNS_INTERNAL_H
#define DNS_INTERNAL_H
#include "dns.h"

#define DNS_HOST_MAXLEN (256)
#define DNS_HM_BUCKET_SZ (32)
#define DNS_MAX_HOSTS (512)

struct dns_item
{
  char name[DNS_HOST_MAXLEN+1];
  struct in_addr addr;
  uint32_t lastuse;
};

struct dns_lru
{
  struct dns_item items[DNS_MAX_HOSTS];
};

void dns_lru_init(struct dns_lru * c);

void dns_lru_put(struct dns_lru * c, const char * name, struct in_addr val);
bool dns_lru_get(struct dns_lru * c, const char * name, struct in_addr * val);
void dns_lru_del(struct dns_lru * c, const char * name);

size_t dns_lru_keyidx(const char * name);

struct dns_state
{
  struct dns_lru mapping;
};

#endif
