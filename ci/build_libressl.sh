#!/bin/sh -e
# build libressl (for GitHub workflow)

git clone --depth 1 -b "${LIBRESSL_VERSION}" https://github.com/libressl/portable.git libressl
cd libressl
./autogen.sh
./configure --prefix=$PWD/build
make -j"$(nproc 2> /dev/null || sysctl -n hw.ncpu)" install
