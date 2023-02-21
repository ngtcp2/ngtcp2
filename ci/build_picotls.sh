#!/bin/sh -e
# build picotls (for GitHub workflow)

if [ "${OPENSSL}" = "openssl1" ]; then
    WORKSPACE=picotls-openssl1
else
    WORKSPACE=picotls-openssl3
fi

git clone https://github.com/h2o/picotls/ "${WORKSPACE}"
cd "${WORKSPACE}"
git checkout "${PICOTLS_VERSION}"
git submodule update --init
mkdir build
cd build
if [ "${OPENSSL}" = "openssl1" ]; then
    PKG_CONFIG_PATH=$PWD/../../openssl1/build/lib/pkgconfig
else
    PKG_CONFIG_PATH=$PWD/../../openssl3/build/lib/pkgconfig:$PWD/../../openssl3/build/lib64/pkgconfig
fi

export PKG_CONFIG_PATH

cmake -DCMAKE_POSITION_INDEPENDENT_CODE=ON ..

make -j"$(nproc 2> /dev/null || sysctl -n hw.ncpu)"
