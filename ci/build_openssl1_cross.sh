#!/bin/sh -e
# build patched openssl (for GitHub workflow) for $HOST and $OSCC
# (os/compiler).

git clone --depth 1 -b OpenSSL_1_1_1s+quic https://github.com/quictls/openssl
cd openssl
./Configure --cross-compile-prefix="$HOST"- --prefix=$PWD/build "$OSCC"
make -j$(nproc)
make install_sw
