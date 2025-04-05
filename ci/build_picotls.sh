#!/bin/sh -e
# build picotls (for GitHub workflow)

WORKSPACE=picotls-"${OPENSSL}"

mkdir "${WORKSPACE}"
cd "${WORKSPACE}"
git init
git remote add origin https://github.com/h2o/picotls
git fetch origin --depth 1 "${PICOTLS_VERSION}"
git checkout "${PICOTLS_VERSION}"
git submodule update --init --depth 1

case "${OPENSSL}" in
    "openssl1")
        PKG_CONFIG_PATH=$PWD/../openssl1/build/lib/pkgconfig
        ;;
    "openssl3")
        PKG_CONFIG_PATH=$PWD/../openssl3/build/lib/pkgconfig:$PWD/../openssl3/build/lib64/pkgconfig
        ;;
    "ossl")
        PKG_CONFIG_PATH=$PWD/../ossl/build/lib/pkgconfig:$PWD/../ossl/build/lib64/pkgconfig
        ;;
    "libressl")
        PKG_CONFIG_PATH=$PWD/../libressl/build/lib/pkgconfig:$PWD/../libressl/build/lib/pkgconfig
        ;;
    *)
        echo "unsupported OpenSSL: ${OPENSSL}"
        exit 1
        ;;
esac

export PKG_CONFIG_PATH

cmake -B build -DCMAKE_POSITION_INDEPENDENT_CODE=ON

make -j"$(nproc 2> /dev/null || sysctl -n hw.ncpu)" -C build
