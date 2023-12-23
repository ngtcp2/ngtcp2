#!/bin/sh -e
# wolfssl (for GitHub workflow)

git clone --depth 1 -b "${WOLFSSL_VERSION}" https://github.com/wolfSSL/wolfssl
cd wolfssl
autoreconf -i
./configure --prefix=$PWD/build --enable-all --enable-quic \
            --enable-aesni --enable-harden \
            --disable-sha224 --disable-dsa --disable-md5
make -j"$(nproc 2> /dev/null || sysctl -n hw.ncpu)"
make install
