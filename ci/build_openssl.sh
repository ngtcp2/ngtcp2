#!/bin/sh
#build last openssl master (for Travis)

cd ..
git clone --depth 1 -b openssl-quic-draft-22 https://github.com/tatsuhiro-t/openssl
cd openssl
./config enable-tls1_3 --prefix=$PWD/build
make -j$(nproc)
make install_sw
cd ..
