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
  "src/addrmapper.c"
  "src/blocking.c"
  "src/base.c"
  "src/dns.c"
  "src/dsa.c"
  "src/elg.c"
  "src/eddsa.c"
  "src/bn.c"
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
  "src/i2p_crypto.c"
  "src/main.c"
)

set(REF10_SRC
  "src/ref10/fe_0.c"
  "src/ref10/fe_1.c"
  "src/ref10/fe_add.c"
  "src/ref10/fe_cmov.c"
  "src/ref10/fe_copy.c"
  "src/ref10/fe_frombytes.c"
  "src/ref10/fe_invert.c"
  "src/ref10/fe_isnegative.c"
  "src/ref10/fe_isnonzero.c"
  "src/ref10/fe_mul.c"
  "src/ref10/fe_neg.c"
  "src/ref10/fe_pow22523.c"
  "src/ref10/fe_sq2.c"
  "src/ref10/fe_sq.c"
  "src/ref10/fe_sub.c"
  "src/ref10/fe_tobytes.c"
  "src/ref10/ge_add.c"
  "src/ref10/ge_double_scalarmult.c"
  "src/ref10/ge_frombytes.c"
  "src/ref10/ge_madd.c"
  "src/ref10/ge_msub.c"
  "src/ref10/ge_p1p1_to_p2.c"
  "src/ref10/ge_p1p1_to_p3.c"
  "src/ref10/ge_p2_0.c"
  "src/ref10/ge_p2_dbl.c"
  "src/ref10/ge_p3_0.c"
  "src/ref10/ge_p3_dbl.c"
  "src/ref10/ge_p3_tobytes.c"
  "src/ref10/ge_p3_to_cached.c"
  "src/ref10/ge_p3_to_p2.c"
  "src/ref10/ge_precomp_0.c"
  "src/ref10/ge_scalarmult_base.c"
  "src/ref10/ge_sub.c"
  "src/ref10/ge_tobytes.c"
  "src/ref10/keypair.c"
  "src/ref10/open.c"
  "src/ref10/sc_muladd.c"
  "src/ref10/sc_reduce.c"
  "src/ref10/sign.c"
  "src/ref10/verify.c"
  "src/ref10/sha512.c"
)


add_executable(${EXE} ${TRANS2P_SRC} ${REF10_SRC})
target_link_libraries(${EXE} ${OPENSSL_LIBRARIES} ${ZLIB_LIBRARIES})
