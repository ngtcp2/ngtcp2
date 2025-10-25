#!/bin/bash -eu

autoreconf -i
./configure --disable-dependency-tracking --enable-lib-only
make -j$(nproc)

"$(dirname "$(realpath "${BASH_SOURCE[0]}")")"/build_fuzzer.sh

zip -j $OUT/decode_frame_seed_corpus.zip fuzz/corpus/decode_frame/*
zip -j $OUT/ksl_seed_corpus.zip fuzz/corpus/ksl/*
zip -j $OUT/read_write_pkt.zip fuzz/corpus/read_write_pkt/*
zip -j $OUT/read_write_handshake_pkt.zip fuzz/corpus/read_write_handshake_pkt/*
