#ifndef PACKET_H
#define PACKET_H
#include "common.h"
#include "i2cp.h"

struct packet_state;

bool translate_i2cp_to_ip(struct packet_state * st, struct i2cp_payload * payload, uint8_t * ippkt_buf, uint16_t * sz);

bool translate_ip_to_i2cp(struct packet_state * st, uint8_t * ippkt_buf, uint16_t sz, struct i2cp_payload * payload, struct i2p_dest ** todest);



bool ip_dnsquery(uint8_t * ippkt_buf, size_t bufsz, uint8_t * dnsquery, size_t qsz);

#endif
