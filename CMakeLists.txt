cmake_minimum_required( VERSION 2.8.12 )
cmake_policy( VERSION 2.8.12)

set(EXE trans2p)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c11 -g -Wall")

include(FindPackageHandleStandardArgs)
include(GNUInstallDirs)

set(TRANS2P_SRC
  "src/blocking.c"
  "src/main.c"
  "src/evloop.c"
  "src/i2cp.c"
  "src/evloop_epoll.c"
  "src/tun_linux.c"
  "src/tun_bsd.c"
  "src/tun_win32.c"
)

add_executable(${EXE} ${TRANS2P_SRC})
