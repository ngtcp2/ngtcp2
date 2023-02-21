#!/bin/sh -e
# build patched openssl (for GitHub workflow)

git clone --depth 1 -b OpenSSL_"${OPENSSL1_VERSION}" https://github.com/quictls/openssl openssl1
cd openssl1
./config --prefix=$PWD/build
make -j"$(nproc 2> /dev/null || sysctl -n hw.ncpu)"
make install_sw
