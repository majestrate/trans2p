cmake_minimum_required( VERSION 2.8.12 )
cmake_policy( VERSION 2.8.12)

set(EXE trans2p)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c11 -g -Wall")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -g -Wall")

include(FindPackageHandleStandardArgs)
include(GNUInstallDirs)
find_package(OpenSSL)
find_package(ZLIB)

set(TRANS2P_SRC
  "src/blocking.c"
  "src/dns.c"
  "src/main.c"
  "src/util.c"
  "src/ini.c"
  "src/evloop.c"
  "src/i2cp.c"
  "src/packet.c"
  "src/evloop_epoll.c"
  "src/sock.c"
  "src/tun.c"
  "src/tun_linux.c"
  "src/tun_bsd.c"
  "src/tun_win32.c"
  "src/i2p_crypto.cpp"
  "src/i2pd/base.cpp"
  "src/i2pd/signature.cpp"
  "src/i2pd/crypto.cpp"
  "src/i2pd/cpu.cpp"
)


add_executable(${EXE} ${TRANS2P_SRC})
target_link_libraries(${EXE} ${OPENSSL_LIBRARIES} ${ZLIB_LIBRARIES})
