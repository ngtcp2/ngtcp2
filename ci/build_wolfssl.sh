#!/bin/sh -e
# wolfssl (for GitHub workflow)

git clone --depth 1 -b "${WOLFSSL_VERSION}" https://github.com/wolfSSL/wolfssl
cd wolfssl
autoreconf -i
./configure --prefix=$PWD/build --enable-all --enable-quic
make -j"$(nproc 2> /dev/null || sysctl -n hw.ncpu)"
make install
