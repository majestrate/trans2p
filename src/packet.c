#include "packet_internal.h"
#include "i2cp_proto.h"

bool streaming_to_tcpip(struct packet_state * st, struct i2cp_payload * payload, uint8_t * pktbuf, uint16_t * sz)
{
  return false;
}

bool translate_i2cp_to_ip(struct packet_state * st, struct i2cp_payload * payload, uint8_t * pktbuf, size_t pktsz, uint16_t * sz)
{
  
  switch(payload->proto)
  {
  case STREAMING:
    return streaming_to_tcpip(st, payload, pktbuf, sz);
  }
  return false;
}


bool translate_ip_to_i2cp(struct packet_state * st, uint8_t * pkt, uint16_t pktsz, struct i2cp_payload * p, struct i2p_dest ** todest)
{
  return false;
}
