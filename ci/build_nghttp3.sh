#!/bin/sh -e
# build nghttp3 (for GitHub workflow)

git clone https://github.com/ngtcp2/nghttp3
cd nghttp3
git checkout "${NGHTTP3_VERSION}"
autoreconf -i
./configure --prefix=$PWD/build --enable-lib-only
make -j"$(nproc 2> /dev/null || sysctl -n hw.ncpu)" check
make install
