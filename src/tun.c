#include "tun.h"
#include "packet.h"

struct tun_send
{
  struct packet_state * pkt;
  struct i2cp_state * i2cp;
  struct i2cp_payload payload; 
};

static void tunif_process_packet(uint8_t * pkt, uint16_t sz, void * user)
{
  struct tun_send * send = user;
  struct i2p_dest * dest = NULL;
  if(translate_ip_to_i2cp(send->pkt, pkt, sz, &send->payload, &dest))
  {
    i2cp_send_payload(send->i2cp, dest, &send->payload);
  }
}

void tunif_tick(struct tunif * t, struct i2cp_state * st, struct packet_state * pkt)
{
  struct tun_send send;
  send.i2cp = st;
  send.pkt = pkt;
  ringbuf_flush(&t->read, &tunif_process_packet, &send);
}
