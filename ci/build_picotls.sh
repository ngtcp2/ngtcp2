#!/bin/sh -e
# build picotls (for GitHub workflow)

git clone https://github.com/h2o/picotls/
cd picotls
git checkout a71a0e16ccb68e114a42e996a8383cb54d67f0b7
git submodule update --init
mkdir build
cd build
PKG_CONFIG_PATH=$PWD/../../openssl/build/lib/pkgconfig:$PWD/../../openssl/build/lib64/pkgconfig cmake -DCMAKE_POSITION_INDEPENDENT_CODE=ON ..
make -j"$(nproc 2> /dev/null || sysctl -n hw.ncpu)"
