#!/bin/sh -e
# build picotls (for GitHub workflow)

if [ "${OPENSSL}" = "openssl1" ]; then
    WORKSPACE=picotls-openssl1
else
    WORKSPACE=picotls-openssl3
fi

mkdir "${WORKSPACE}"
cd "${WORKSPACE}"
git init
git remote add origin https://github.com/h2o/picotls
git fetch origin --depth 1 "${PICOTLS_VERSION}"
git checkout "${PICOTLS_VERSION}"
git submodule update --init --depth 1
if [ "${OPENSSL}" = "openssl1" ]; then
    PKG_CONFIG_PATH=$PWD/../openssl1/build/lib/pkgconfig
else
    PKG_CONFIG_PATH=$PWD/../openssl3/build/lib/pkgconfig:$PWD/../openssl3/build/lib64/pkgconfig
fi

export PKG_CONFIG_PATH

cmake -B build -DCMAKE_POSITION_INDEPENDENT_CODE=ON

make -j"$(nproc 2> /dev/null || sysctl -n hw.ncpu)" -C build
