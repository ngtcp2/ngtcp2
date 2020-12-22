#!/bin/sh -e
# build patched openssl (for GitHub workflow)

cd ..
git clone --depth 1 -b OpenSSL_1_1_1g-quic-draft-33 https://github.com/tatsuhiro-t/openssl
cd openssl
./config enable-tls1_3 --prefix=$PWD/build
make -j$(nproc)
make install_sw
cd ..
