#!/bin/sh -e
# build patched openssl (for GitHub workflow)

git clone --depth 1 -b openssl-"${OPENSSL3_VERSION}" https://github.com/quictls/openssl openssl3
cd openssl3
./config --prefix=$PWD/build --openssldir=/etc/ssl
make -j"$(nproc 2> /dev/null || sysctl -n hw.ncpu)"
make install_sw
