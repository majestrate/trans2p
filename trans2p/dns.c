#include "dns_internal.h"
#include "util.h"
#include "i2p_endian.h"
#include <stdio.h>
#include <string.h>

void dns_state_init(struct dns_state * st)
{
  dns_lru_init(&st->lru);
}

bool parse_dns_message(uint8_t * data, size_t sz, struct dns_msg * msg)
{
  if(sz < sizeof(struct dns_msg_hdr)) return false;
  msg->hdr = (struct dns_msg_hdr *) data;
  data += sizeof(struct dns_msg_hdr);
  if(msg->hdr->qr)
  {
    if(ntohs(msg->hdr->qdcount))
    {
      uint8_t l = *data;
      char * ptr =  msg->qname;
      while(l)
      {
        data ++;
        while(l--)
        {
          *ptr = *data;
          ptr ++;
          data ++;
        }
        l = *data;
        if(l)
        {
          *ptr = '.';
          ptr++;
        }
      }
      *ptr = 0;
      data ++;
      msg->qtype = bufbe16toh(data);
      data += 2;
      msg->qclass = bufbe16toh(data);
    }
  }
  return true;
}

void dns_state_handle_msg(struct dns_state * st, struct dns_msg * msg)
{
  if(msg->hdr->qr)
  {
    printf("got dns query for address: %s %d\n", msg->qname, msg->qclass);
  }
  else
  {
    printf("got dns non query?\n");
  }
}

void dns_state_process_data(struct dns_state * st, uint8_t * data, size_t sz)
{
  hexdump(data, sz);
  if(parse_dns_message(data, sz, &st->msgbuf))
  {
    dns_state_handle_msg(st, &st->msgbuf);
  }
  else
    printf("failed to parse dns message\n");
}


void dns_lru_init(struct dns_lru * lru)
{
  memset(lru, 0, sizeof(struct dns_lru));
}
