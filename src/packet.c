#include "packet_internal.h"


bool translate_i2cp_to_ip(struct packet_state * st, struct i2cp_payload * payload, uint8_t * pktbuf, uint16_t * sz)
{
  return false;
}


bool translate_ip_to_i2cp(struct packet_state * st, uint8_t * pkt, uint16_t sz, struct i2cp_payload * p, struct i2p_dest ** todest)
{
  return false;
}
