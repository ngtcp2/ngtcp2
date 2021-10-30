#!/bin/sh -e
# build patched openssl (for GitHub workflow)

git clone -b openssl-3.0.0+quic https://github.com/quictls/openssl
cd openssl
git checkout e034c2d95e31a383db94ea626c41d42a2b074f18
./config --prefix=$PWD/build
make -j$(nproc)
make install_sw
