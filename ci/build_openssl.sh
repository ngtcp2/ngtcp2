#!/bin/sh
#build last openssl master (for Travis)

cd ..
git clone -b tlsv1.3-28 --depth 1 https://github.com/tatsuhiro-t/openssl
cd openssl
./config enable-tls1_3 --prefix=$PWD/build
make -j$(nproc)
make install_sw
cd ..
