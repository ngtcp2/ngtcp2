#!/bin/bash -eu

autoreconf -i
./configure --enable-lib-only
make -j$(nproc)

$CXX $CXXFLAGS -std=c++17 -Ilib/includes -Ilib -I. -DHAVE_CONFIG_H \
     fuzz/decode_frame.cc -o $OUT/decode_frame \
     $LIB_FUZZING_ENGINE lib/.libs/libngtcp2.a

$CXX $CXXFLAGS -std=c++17 -Ilib/includes -Ilib -I. -DHAVE_CONFIG_H \
     fuzz/ksl.cc -o $OUT/ksl \
     $LIB_FUZZING_ENGINE lib/.libs/libngtcp2.a

zip -j $OUT/decode_frame_seed_corpus.zip fuzz/corpus/decode_frame/*
zip -j $OUT/ksl_seed_corpus.zip fuzz/corpus/ksl/*
