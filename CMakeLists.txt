cmake_minimum_required( VERSION 2.8.12 )
cmake_policy( VERSION 2.8.12)

set(EXE trans2p)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c11")

include(FindPackageHandleStandardArgs)
include(GNUInstallDirs)

set(TRANS2P_SRC
  "src/blocking.c"
  "src/main.c"
  "src/evloop.c"
  "src/impl_epoll.c"
)

add_executable(${EXE} ${TRANS2P_SRC})
