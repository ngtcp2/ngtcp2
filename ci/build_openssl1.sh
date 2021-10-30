#!/bin/sh -e
# build patched openssl (for GitHub workflow)

git clone -b OpenSSL_1_1_1l+quic https://github.com/quictls/openssl
cd openssl
git checkout 5b312bf1bd1361216a817f338eca3830b7c15d85
./config --prefix=$PWD/build
make -j$(nproc)
make install_sw
