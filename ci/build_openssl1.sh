#!/bin/sh -e
# build patched openssl (for GitHub workflow)

git clone --depth 1 -b OpenSSL_1_1_1l+quic https://github.com/quictls/openssl
cd openssl
./config --prefix=$PWD/build
make -j$(nproc)
make install_sw
