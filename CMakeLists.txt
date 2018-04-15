cmake_minimum_required( VERSION 2.8.12 )
cmake_policy( VERSION 2.8.12)

set(EXE trans2p)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c11 -g -Wall")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17 -g -Wall")

include(FindPackageHandleStandardArgs)
include(GNUInstallDirs)
find_package(OpenSSL)
find_package(ZLIB)


set(HASH "sha2_openssl")
set(RANDOM "rand_openssl")
set(BUILD "STATIC")
add_subdirectory(iroha-ed25519)
include_directories(iroha-ed25519/include)

set(TRANS2P_SRC
  "trans2p/addrmapper.c"
  "trans2p/blocking.c"
  "trans2p/base.c"
  "trans2p/dns.c"
  "trans2p/dsa.c"
  "trans2p/elg.c"
  "trans2p/eddsa.c"
  "trans2p/bn.c"
  "trans2p/util.c"
  "trans2p/ini.c"
  "trans2p/evloop.c"
  "trans2p/i2cp.c"
  "trans2p/packet.c"
  "trans2p/evloop_epoll.c"
  "trans2p/sock.c"
  "trans2p/tun.c"
  "trans2p/tun_linux.c"
  "trans2p/tun_bsd.c"
  "trans2p/tun_win32.c"
  "trans2p/i2p_crypto.c"
  "trans2p/main.c"
)

add_executable(${EXE} ${TRANS2P_SRC})
target_link_libraries(${EXE} ${OPENSSL_LIBRARIES} ${ZLIB_LIBRARIES} ed25519)
