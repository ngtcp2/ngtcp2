#!/bin/sh -e
# build patched openssl (for GitHub workflow) for $HOST and $OSCC
# (os/compiler).

git clone --depth 1 -b OpenSSL_1_1_1q+quic https://github.com/quictls/openssl
cd openssl
curl -L https://github.com/openssl/openssl/commit/60f011f584d80447e86cae1d1bd3ae24bc13235b.patch -o memcmp.patch
patch -p1 < memcmp.patch
./Configure --cross-compile-prefix="$HOST"- --prefix=$PWD/build "$OSCC"
make -j$(nproc)
make install_sw
