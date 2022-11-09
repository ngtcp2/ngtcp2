#!/bin/sh -e
# build patched openssl (for GitHub workflow)

git clone --depth 1 -b OpenSSL_1_1_1s+quic https://github.com/quictls/openssl
cd openssl
./config --prefix=$PWD/build
make -j"$(nproc 2> /dev/null || sysctl -n hw.ncpu)"
make install_sw
