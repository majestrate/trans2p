#include "blocking.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>

bool blocking_tcp_connect(const char * host, int port, int * fd)
{
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if(sockfd == -1) return false;
  
 
  struct sockaddr_in addr;

  inet_pton(AF_INET, host, &addr.sin_addr);
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  
  if( connect(sockfd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) == -1)
  {
    perror("connect()");
    close(sockfd);
    return false;
  }
  *fd = sockfd;
  return true;
}
