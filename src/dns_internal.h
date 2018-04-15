#ifndef DNS_INTERNAL_H
#define DNS_INTERNAL_H
#include "dns.h"
#include "evloop.h"
#include "addrmapper_internal.h"
#include "common.h"

struct dns_msg_hdr
{
		unsigned qid:16;

#if BIG_ENDIAN
		unsigned qr:1;
		unsigned opcode:4;
		unsigned aa:1;
		unsigned tc:1;
		unsigned rd:1;

		unsigned ra:1;
		unsigned unused:3;
		unsigned rcode:4;
#else
		unsigned rd:1;
		unsigned tc:1;
		unsigned aa:1;
		unsigned opcode:4;
		unsigned qr:1;

		unsigned rcode:4;
		unsigned unused:3;
		unsigned ra:1;
#endif

		unsigned qdcount:16;
		unsigned ancount:16;
		unsigned nscount:16;
		unsigned arcount:16;
};

struct dns_msg
{
  struct dns_msg_hdr * hdr;
  char qname[256];
  uint16_t qtype;
  uint16_t qclass;
};

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

bool dns_lru_has(struct dns_lru * c, const char * name);
void dns_lru_put(struct dns_lru * c, const char * name, struct in_addr val);
bool dns_lru_get(struct dns_lru * c, const char * name, struct in_addr * val);
void dns_lru_del(struct dns_lru * c, const char * name);

size_t dns_lru_keyidx(const char * name);

struct dns_state
{
  struct addr_mapper addr;
  struct dns_lru lru;
  struct ev_event ev;
  struct dns_msg msgbuf;
};

#endif
