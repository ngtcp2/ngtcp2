#!/bin/sh -e
# build nghttp3 (for GitHub workflow)

mkdir nghttp3
cd nghttp3
git init
git remote add origin https://github.com/ngtcp2/nghttp3
git fetch origin --depth 1 "${NGHTTP3_VERSION}"
git checkout "${NGHTTP3_VERSION}"
git submodule update --init --depth 1
autoreconf -i
./configure --disable-dependency-tracking --prefix=$PWD/build --enable-lib-only
make -j"$(nproc 2> /dev/null || sysctl -n hw.ncpu)" check
make install
