#include "tun_linux.h"
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

static bool if_settun(int fd, int * if_index)
{
  struct ifreq r;
  memset(&r, 0, sizeof(struct ifreq));
  if(ioctl(fd, SIOGIFINDEX, &r) == -1) return false;
  *if_index = r.ifr_ifindex;
  if(ioctl(fd, SIOCGIFFLAGS, &r) == -1) return false;
  r.ifr_flags = IFF_TUN;
  return ioctl(fd, SIOCSIFFLAGS, &r) != -1;
}

static bool if_setname(int fd, const char * ifname, int if_index)
{
  struct ifreq r;
  memset(&r, 0, sizeof(struct ifreq));
  r.ifr_ifindex = if_index;
  if(ioctl(fd, SIOCGIFNAME, &r) == -1) return false;
  /* name matches desired value already ? */
  if(!strncmp(r.ifr_name, ifname, sizeof(r.ifr_name))) return true;
  
  strncpy(r.ifr_newname, ifname, sizeof(r.ifr_newname));
  r.ifr_ifindex = 0;
  return ioctl(fd, SIOCSIFNAME, &r) != -1;
  
}

static bool if_setmtu(int fd, int mtu, int if_index)
{
  struct ifreq r;
  memset(&r, 0, sizeof(struct ifreq));
  r.ifr_ifindex = if_index;
  r.ifr_mtu = mtu;
  return ioctl(fd, SIOCSIFMTU, &r) != -1;
}

static bool if_up(int fd, int if_index)
{
  struct ifreq r;
  memset(&r, 0, sizeof(struct ifreq));
  r.ifr_ifindex = if_index;
  if(ioctl(fd, SIOCGIFFLAGS, &r) == -1) return false;
  r.ifr_flags |= IFF_UP;
  return ioctl(fd, SIOCSIFFLAGS, &r) != -1;
}

int ev_linux_opentun(struct ev_impl * impl, struct tun_param param)
{
  int ifindex;
  int fd = -1;
  fd = open("/dev/net/tun", O_RDWR);
  if(fd != -1)
  {
    if(!if_settun(fd, &ifindex))
    {
      perror("if_settun()");
      close(fd);
      return -1;
    }
    if(!if_setname(fd, param.ifname, ifindex))
    {
      perror("if_setname()");
      close(fd);
      return -1;
    }
    if(!if_setmtu(fd, param.mtu, ifindex))
    {
      perror("if_setmtu()");
      close(fd);
      return -1;
    }
    if(!if_up(fd, ifindex))
    {
      perror("if_up()");
      close(fd);
      return -1;
    }
  }
  return fd;
}
