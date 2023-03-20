#!/bin/sh -e
# build patched openssl (for GitHub workflow)

if [ "${OPENSSL}" = "openssl1" ]; then
    WORKSPACE=openssl1
    BRANCH="OpenSSL_${OPENSSL1_VERSION}"
else
    WORKSPACE=openssl3
    BRANCH="openssl-${OPENSSL3_VERSION}"
fi

git clone --depth 1 -b "${BRANCH}" https://github.com/quictls/openssl "${WORKSPACE}"
cd "${WORKSPACE}"
./config --prefix=$PWD/build --openssldir=/etc/ssl
make -j"$(nproc 2> /dev/null || sysctl -n hw.ncpu)"
make install_sw
