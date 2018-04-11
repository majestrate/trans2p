#include "tun_linux.h"
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

static bool if_settun(int fd, const char * ifname, int * if_index)
{
  struct ifreq r;
  memset(&r, 0, sizeof(struct ifreq));
  r.ifr_flags = IFF_TUN;
  strncpy(r.ifr_name, ifname, sizeof(r.ifr_name));
  if(ioctl(fd, TUNSETIFF, &r) == -1) return false;
  *if_index = r.ifr_ifindex;
  return true;
}

static bool if_setaddr(const char * ifname, struct in_addr addr)
{
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if(fd == -1) return false;
  struct ifreq r;
  memset(&r, 0, sizeof(struct ifreq));
  strncpy(r.ifr_name, ifname, sizeof(r.ifr_name));
  struct sockaddr_in * a = (struct sockaddr_in * ) &r.ifr_addr;
  a->sin_family = AF_INET;
  memcpy(&a->sin_addr, &addr, sizeof(struct in_addr));
  bool success = ioctl(fd, SIOCSIFADDR, &r) != -1;
  close(fd);
  return success;
}

static bool if_setnetmask(const char * ifname, struct in_addr addr)
{
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if(fd == -1) return false;
  struct ifreq r;
  memset(&r, 0, sizeof(struct ifreq));
  strncpy(r.ifr_name, ifname, sizeof(r.ifr_name));
  struct sockaddr_in * a = (struct sockaddr_in * ) &r.ifr_netmask;
  a->sin_family = AF_INET;
  memcpy(&a->sin_addr, &addr, sizeof(struct in_addr));
  bool success = ioctl(fd, SIOCSIFNETMASK, &r) != -1;
  close(fd);
  return success;
}

static bool if_up(const char * ifname)
{
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if(fd == -1) return false;
  struct ifreq r;
  memset(&r, 0, sizeof(struct ifreq));
  strncpy(r.ifr_name, ifname, sizeof(r.ifr_name));
  if(ioctl(fd, SIOCGIFFLAGS, &r) == -1)
  {
    close(fd);
    return false;
  }
  r.ifr_flags |= IFF_UP | IFF_RUNNING;
  bool success = ioctl(fd, SIOCSIFFLAGS, &r) != -1;
  close(fd);
  return success;
}

int ev_linux_opentun(struct ev_impl * impl, struct tun_param param)
{
  int ifindex = -1;
  int fd = -1;
  fd = open("/dev/net/tun", O_RDWR);
  if(fd != -1)
  {
    if(!if_settun(fd, param.ifname, &ifindex))
    {
      perror("if_settun()");
      close(fd);
      return -1;
    }
    if(!if_setaddr(param.ifname, param.addr))
    {
      perror("if_setaddr()");
      close(fd);
      return -1;
    }
    if(!if_setnetmask(param.ifname, param.netmask))
    {
      perror("if_setnetmask()");
      close(fd);
      return -1;
    }
    if(!if_up(param.ifname))
    {
      perror("if_up()");
      close(fd);
      return -1;
    }
  }
  return fd;
}
