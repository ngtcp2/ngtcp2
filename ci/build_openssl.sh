#!/bin/sh
#build last openssl master (for Travis)

cd ..
git clone --depth 1 https://github.com/openssl/openssl
cd openssl
./config enable-tls1_3 --prefix=$PWD/build
make -j$(nproc)
make install_sw
cd ..
