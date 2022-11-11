#!/bin/sh -e
# build picotls (for GitHub workflow)

git clone https://github.com/h2o/picotls/
cd picotls
git checkout 67ba66e91728316152fc2c2172710ca4c2236027
git submodule update --init
mkdir build
cd build
PKG_CONFIG_PATH=$PWD/../../openssl/build/lib/pkgconfig:$PWD/../../openssl/build/lib64/pkgconfig cmake -DCMAKE_POSITION_INDEPENDENT_CODE=ON ..
make -j"$(nproc 2> /dev/null || sysctl -n hw.ncpu)"
