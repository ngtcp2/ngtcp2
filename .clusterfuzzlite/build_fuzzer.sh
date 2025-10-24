#!/bin/bash -eu

FUZZERS=(
    decode_frame
    ksl
    rob
    read_write_pkt
    read_write_handshake_pkt
)

for fuzzer in "${FUZZERS[@]}"; do
    $CXX $CXXFLAGS -std=c++17 -Ilib/includes -Ilib -I. -DHAVE_CONFIG_H \
         fuzz/${fuzzer}.cc -o $OUT/${fuzzer} \
         $LIB_FUZZING_ENGINE lib/.libs/libngtcp2.a
done
