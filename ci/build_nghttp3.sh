#!/bin/sh -e
# build nghttp3 (for GitHub workflow)

git clone https://github.com/ngtcp2/nghttp3
cd nghttp3
git checkout 2eda009319eceec3544d7a164b52be873a928ac0
autoreconf -i
./configure --prefix=$PWD/build --enable-lib-only
make -j"$(nproc 2> /dev/null || sysctl -n hw.ncpu)" check
make install
