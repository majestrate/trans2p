#ifndef CONFIG_H
#define CONFIG_H

#ifdef __linux__
#define _USE_EPOLL
#else
#ifdef __freebsd__
#define _USE_KQUEUE
#endif
#endif

#endif
