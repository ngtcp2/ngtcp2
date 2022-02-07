#!/bin/sh -e
# build picotls (for GitHub workflow)

git clone https://github.com/h2o/picotls/
cd picotls
git checkout 047c5fe20bb9ea91c1caded8977134f19681ec76
patch -p1 < ../ci/0001-Fix-build-errors.patch
git submodule update --init
mkdir build
cd build
PKG_CONFIG_PATH=$PWD/../../openssl/build/lib/pkgconfig cmake -DCMAKE_POSITION_INDEPENDENT_CODE=ON ..
make -j$(nproc)
