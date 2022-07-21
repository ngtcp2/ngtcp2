#!/bin/sh -e
# build picotls (for GitHub workflow)

git clone https://github.com/h2o/picotls/
cd picotls
git checkout 7970614ad049d194fe1691bdf0cc66c6930a3a2f
git submodule update --init
mkdir build
cd build
PKG_CONFIG_PATH=$PWD/../../openssl/build/lib/pkgconfig cmake -DCMAKE_POSITION_INDEPENDENT_CODE=ON ..
make -j"$(nproc 2> /dev/null || sysctl -n hw.ncpu)"
