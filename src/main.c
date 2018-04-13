/**
   trans2p main
 */
#include "evloop.h"
#include "blocking.h"
#include "i2cp_internal.h"
#include "i2cp_msg.h"
#include "i2p_endian.h"
#include "i2p_crypto.h"
#include "packet_internal.h"
#include "tun.h"
#include "util.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>

struct trans2p
{
  struct ev_impl * impl;
  struct ev_api api;
  struct ev_event i2cp_ev;
  struct ev_event tun_ev;
  struct i2cp_state i2cp;
  int i2cp_fd;
  bool running;
  struct i2p_privkeybuf privkey;
  struct i2p_dest ourdest;
  struct i2p_elg lskey;
  struct i2cp_payload payload;
  struct packet_state pkt;
  struct tunif tun;
  uint8_t buf[65536];
};

struct handler
{
  struct trans2p * t;

  uint8_t readbuf[1024];
  
  void (*read)(ssize_t, struct handler *);  
  void (*write)(struct handler *);
};

void tun_onpacket(ssize_t sz, struct handler * h)
{
  if(sz > 0 && sz < 65536)
  {
    uint16_t readsz = sz;
    ringbuf_append(&h->t->tun.read, h->readbuf, readsz);
  }
}

void i2cp_onread(ssize_t sz, struct handler * h)
{
  //hexdump(h->buf, sz);
  if(sz > 0)
    i2cp_offer(&h->t->i2cp, h->readbuf, sz); 
}

void onsessionstatus(uint8_t * data, uint32_t sz, struct i2cp_state * st, void * user)
{
  (void) user;
  uint16_t sid = bufbe16toh(data);
  data += 2;
  switch(*data)
  {
  case DESTROYED:
    printf("session destroyed: %d\n", sid);
    return;
  case CREATED:
    printf("session created: %d\n", sid);
    st->sid = sid;
    return;
  case UPDATED:
    printf("session updated: %d\n", sid);
    return;
  case INVALID:
    printf("session invalid: %d\n", sid);
    return;
  case REFUSED:
    printf("session refused: %d\n", sid);
    return;
  default:
    printf("session unknown status %d: %d", *data, sid);
    return;
  }
}

void onsetdate(uint8_t * data, uint32_t sz, struct i2cp_state * st, void * user)
{
  struct trans2p * t = user;
  struct i2p_privkeybuf * priv = &t->privkey;
  struct i2p_dest * dest = &t->ourdest;

  i2p_elg_keygen(t->lskey.priv, t->lskey.pub);
  
  uint8_t * buf = t->buf;
  uint8_t * begin = buf;
  memcpy(buf, dest->buf, dest->sz);
  buf += dest->sz;
  // no options
  htobe16buf(buf, 0);
  buf += 2;
  // date
  memcpy(buf, data, 8);
  buf += 8;
  i2p_dest_sign(priv, begin, buf - begin, buf);
  buf += i2p_dest_sigsize(priv);
  i2cp_queue_send(st, CREATESESSION, begin, buf - begin);
}

void onpayload(uint8_t * data, uint32_t sz, struct i2cp_state * st, void * user)
{
  struct trans2p * t = user;
  uint8_t * buf = data;
  // session id
  uint16_t sid = bufbe16toh(buf);
  buf += 2;
  assert(sid == st->sid);
  // msgid
  buf += 4;
  // payload header
  t->payload.ptrlen = bufbe32toh(buf);
  if(t->payload.ptrlen > sz)
  {
    printf("i2cp payload overflow: %d > %d\n", t->payload.ptrlen, sz);
    return;
  }
  buf += 4;
  // payload 
  t->payload.ptr = buf;
  if(i2cp_parse_payload(&t->payload))
  {
    uint16_t ippkt_sz;
    if(translate_i2cp_to_ip(&t->pkt, &t->payload, t->buf, &ippkt_sz))
    {
      ringbuf_append(&t->tun.write, t->buf, ippkt_sz);
    }
    else
      printf("dropping i2cp message, cannot translate\n");
  }
  else
  {
    printf("invalid i2cp payload\n");
  }
}

void onreqvarls(uint8_t * data, uint32_t sz, struct i2cp_state * st, void * user)
{
  struct trans2p * t = user;
  struct i2p_privkeybuf * priv = &t->privkey;
  struct i2p_dest * dest = &t->ourdest;

  uint16_t sid = bufbe16toh(data);
  if(sid != st->sid)
  {
    printf("i2cp session id missmatch %d != %d\n", sid, st->sid);
  }
  
  uint8_t numls = data[2];
  
  uint8_t * buf = t->buf;
  uint8_t * begin = buf;
  // sid
  htobe16buf(buf, st->sid);
  buf += 2;
  // 20 bytes revoke
  memset(buf, 0, 20);
  buf += 20;
  // elg privkey
  memcpy(buf, t->lskey.priv, 256);
  buf += 256;
  // begin LS
  uint8_t * ls_ptr = buf;
  // destination
  memcpy(ls_ptr, dest->buf, dest->sz);
  buf += dest->sz;
  // LS pubkey
  memcpy(buf, t->lskey.pub, 256);
  buf += 256;
  // revoke key
  memcpy(buf, dest->sigkey, 32);
  buf += 32;
  // num leases
  *buf = numls;
  buf ++;
  // leases
  memcpy(buf, data + 3, (numls * 44));
  buf += numls * 44;
  // signature
  i2p_dest_sign(priv, ls_ptr, buf - ls_ptr, buf);
  buf += i2p_dest_sigsize(priv);
  // end
  i2cp_queue_send(st, CREATELS, begin, buf - begin);
  printf("created LS with %d leases\n", numls);
}

static void i2cp_write(void * impl, uint8_t * ptr, uint32_t sz)
{
  struct trans2p * t = (struct trans2p * ) impl;
  int res = write(t->i2cp_fd, ptr, sz);
  if (res == -1) perror("i2cp_write()");
}

void tun_ringbuf_write(uint8_t * ptr, uint16_t sz, void * user)
{
  struct tunif * tun = user;
  write(tun->fd, ptr, sz);
}

void tun_flushwrite(struct handler * h)
{
  struct tunif * tun = &h->t->tun;
  ringbuf_flush(&tun->write, &tun_ringbuf_write, tun);
}

void tick(struct trans2p * t)
{
  // process ip packets
  tunif_tick(&t->tun, &t->i2cp, &t->pkt);
  // process i2cp messages
  i2cp_tick(&t->i2cp);
}

void mainloop(struct trans2p * t)
{
  struct ev_api * api = &t->api;
  struct ev_impl * impl = t->impl;
  struct ev_event ev;
  struct handler * h;
  int res;
  int count;
  printf("mainloop\n");
  do
  {
    res = api->poll(impl, 10, &ev);
    if(res == 0)
    {
      tick(t);
    }
    else if(res > 0)
    {
      h = (struct handler *) ev.ptr;
      if(ev.flags & EV_READ)
      {
        do
        {
          count = read(ev.fd, h->readbuf, sizeof(h->readbuf));
          if(count > 0 && h->read)
          {
            h->read(count, h);
          }
          else if (count == 0)
          {
            // connection closed
            close(ev.fd);
            api->del(impl, ev.fd);
          }
          else if (errno != EAGAIN)
          {
            perror("read");
          }
        }
        while(count > 0);     
      }
      if (ev.flags & EV_WRITE)
      {
        if(h->write)
          h->write(h);
      }
    }
  }
  while(res != -1);
}

int main(int argc, char * argv[])
{
  
  struct trans2p t;

  struct handler tun_handler = {
    .t = &t,
    .read = &tun_onpacket,
    .write = &tun_flushwrite
  };
  
  struct handler i2cp_handler = {
    .t = &t,
    .read = &i2cp_onread,
    .write = NULL
  };
  
  const char * i2cp_addr;
  int i2cp_port;

  if(argc != 4)
  {
    printf("usage %s i2cp_host i2cp_port ifname\n", argv[0]);
    return 1;
  }
  i2cp_addr = argv[1];
  i2cp_port = atoi(argv[2]);
  if(i2cp_port == -1)
  {
    printf("invalid i2cp port %s\n", argv[2]);
    return 1;
  }
  i2p_crypto_init();
  i2cp_state_init(&t.i2cp, &i2cp_write, &t);

  i2cp_set_msghandler(&t.i2cp, SETDATE, &onsetdate, &t);
  i2cp_set_msghandler(&t.i2cp, SESSIONSTATUS, &onsessionstatus, &t);
  i2cp_set_msghandler(&t.i2cp, REQVARLS, &onreqvarls, &t);
  i2cp_set_msghandler(&t.i2cp, PAYLOAD, &onpayload, &t);

  
  struct ev_api * api;
  assert(ev_init(&t.api));
  t.running = true;
  api = &t.api;
  t.impl = api->open();
  assert(t.impl);
  
  struct tun_param tun;
  tun.ifname = argv[3];
  tun.mtu = 1500;
  // TODO: make configurable
  assert(inet_pton(AF_INET, "10.55.0.1", &tun.addr) == 1);
  assert(inet_pton(AF_INET, "255.255.255.0", &tun.netmask) == 1);
  printf("open tun interface %s\n", tun.ifname);
  int tunfd = api->tun(t.impl, tun);
  if(tunfd == -1) return 1;
  t.tun.ev.fd = tunfd;
  t.tun.ev.ptr = &tun_handler;
  t.tun.ev.flags = EV_READ | EV_WRITE;
  api->add(t.impl,  &t.tun.ev);
  tunif_init(&t.tun, tunfd);
  while(t.running)
  {
    printf("generate new identity\n");
    i2p_keygen(&t.privkey);
    i2p_privkey_dest(&t.privkey, &t.ourdest);
    char * buf = (char *) t.buf;
    i2p_dest_tob32addr(&t.ourdest, buf, sizeof(t.buf));
    printf("we are %s\n", buf);
    printf("connecting to %s port %d\n", i2cp_addr, i2cp_port);
    if(blocking_tcp_connect(i2cp_addr, i2cp_port, &t.i2cp_fd))
    {
      printf("connected\n");
      t.i2cp_ev.fd = t.i2cp_fd;
      t.i2cp_ev.ptr = &i2cp_handler;
      t.i2cp_ev.flags = EV_READ;
      assert(api->add(t.impl, &t.i2cp_ev));
      i2cp_begin(&t.i2cp);
      mainloop(&t);
      api->del(t.impl, t.i2cp_fd);
    }
    else
    {
      perror("blocking_tcp_connect()");
      sleep(1);
    }
  }
  api->close(t.impl);
  i2p_crypto_end();
}
