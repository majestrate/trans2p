#include "sock.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

int udp_socket()
{
  return socket(AF_INET, SOCK_DGRAM, 0);
}

bool udp_bind(int fd, const char * addr, int port)
{
  struct sockaddr_in saddr;
  saddr.sin_family = AF_INET;
  saddr.sin_port = htons(port);
  if(inet_pton(AF_INET, addr, &saddr.sin_addr) == -1) return false;
  return bind(fd, (struct sockaddr *) & saddr, sizeof(struct sockaddr_in)) != -1;
}
