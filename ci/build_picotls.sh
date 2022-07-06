#!/bin/sh -e
# build picotls (for GitHub workflow)

git clone https://github.com/h2o/picotls/
cd picotls
git checkout c4b9f6b834fac7533020565c77bd3af5ca2fae6c
git submodule update --init
mkdir build
cd build
PKG_CONFIG_PATH=$PWD/../../openssl/build/lib/pkgconfig cmake -DCMAKE_POSITION_INDEPENDENT_CODE=ON ..
make -j"$(nproc 2> /dev/null || sysctl -n hw.ncpu)"
