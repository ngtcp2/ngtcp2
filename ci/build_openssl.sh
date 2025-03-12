#!/bin/sh -e
# build patched openssl (for GitHub workflow)

if [ "${OPENSSL}" = "openssl1" ]; then
    WORKSPACE=openssl1
    BRANCH="OpenSSL_${OPENSSL1_VERSION}"
    REPO="https://github.com/quictls/openssl"
else
    WORKSPACE=openssl3
    BRANCH="openssl-${OPENSSL3_VERSION}"
    REPO="https://github.com/openssl/openssl"
fi

git clone --depth 1 -b "${BRANCH}" "${REPO}" "${WORKSPACE}"
cd "${WORKSPACE}"
./config --prefix=$PWD/build --openssldir=/etc/ssl
make -j"$(nproc 2> /dev/null || sysctl -n hw.ncpu)"
make install_sw
