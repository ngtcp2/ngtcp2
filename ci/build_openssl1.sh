#!/bin/sh -e
# build patched openssl (for GitHub workflow)

git clone --depth 1 -b OpenSSL_1_1_1q+quic https://github.com/quictls/openssl
cd openssl
curl -L https://github.com/openssl/openssl/commit/60f011f584d80447e86cae1d1bd3ae24bc13235b.patch -o memcmp.patch
patch -p1 < memcmp.patch
./config --prefix=$PWD/build
make -j"$(nproc 2> /dev/null || sysctl -n hw.ncpu)"
make install_sw
