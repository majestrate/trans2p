cmake_minimum_required( VERSION 2.8.12 )
cmake_policy( VERSION 2.8.12)

set(EXE trans2p)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c11 -g -Wall")

include(FindPackageHandleStandardArgs)
include(GNUInstallDirs)
find_package(OpenSSL)
find_package(ZLIB)

include_directories(include)

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

set(REF10_SRC
  "trans2p/ref10/fe_0.c"
  "trans2p/ref10/fe_1.c"
  "trans2p/ref10/fe_add.c"
  "trans2p/ref10/fe_cmov.c"
  "trans2p/ref10/fe_copy.c"
  "trans2p/ref10/fe_frombytes.c"
  "trans2p/ref10/fe_invert.c"
  "trans2p/ref10/fe_isnegative.c"
  "trans2p/ref10/fe_isnonzero.c"
  "trans2p/ref10/fe_mul.c"
  "trans2p/ref10/fe_neg.c"
  "trans2p/ref10/fe_pow22523.c"
  "trans2p/ref10/fe_sq2.c"
  "trans2p/ref10/fe_sq.c"
  "trans2p/ref10/fe_sub.c"
  "trans2p/ref10/fe_tobytes.c"
  "trans2p/ref10/ge_add.c"
  "trans2p/ref10/ge_double_scalarmult.c"
  "trans2p/ref10/ge_frombytes.c"
  "trans2p/ref10/ge_madd.c"
  "trans2p/ref10/ge_msub.c"
  "trans2p/ref10/ge_p1p1_to_p2.c"
  "trans2p/ref10/ge_p1p1_to_p3.c"
  "trans2p/ref10/ge_p2_0.c"
  "trans2p/ref10/ge_p2_dbl.c"
  "trans2p/ref10/ge_p3_0.c"
  "trans2p/ref10/ge_p3_dbl.c"
  "trans2p/ref10/ge_p3_tobytes.c"
  "trans2p/ref10/ge_p3_to_cached.c"
  "trans2p/ref10/ge_p3_to_p2.c"
  "trans2p/ref10/ge_precomp_0.c"
  "trans2p/ref10/ge_scalarmult_base.c"
  "trans2p/ref10/ge_sub.c"
  "trans2p/ref10/ge_tobytes.c"
  "trans2p/ref10/keypair.c"
  "trans2p/ref10/open.c"
  "trans2p/ref10/sc_muladd.c"
  "trans2p/ref10/sc_reduce.c"
  "trans2p/ref10/sign.c"
  "trans2p/ref10/verify.c"
  "trans2p/ref10/sha512.c"
)


add_executable(${EXE} ${TRANS2P_SRC} ${REF10_SRC})
target_link_libraries(${EXE} ${OPENSSL_LIBRARIES} ${ZLIB_LIBRARIES})
