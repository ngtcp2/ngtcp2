#!/bin/sh -e
# build patched openssl (for GitHub workflow)

WORKSPACE="${OPENSSL}"

case "${OPENSSL}" in
    openssl1)
        BRANCH="OpenSSL_${OPENSSL1_VERSION}"
        REPO="https://github.com/quictls/openssl"
        ;;
    openssl3)
        BRANCH="openssl-${OPENSSL3_VERSION}"
        REPO="https://github.com/quictls/openssl"
        ;;
    ossl)
        BRANCH="openssl-${OSSL_VERSION}"
        REPO="https://github.com/openssl/openssl"
        ;;
    *)
        echo "unsupported OpenSSL: ${OPENSSL}"
        exit 1
        ;;
esac

git clone --depth 1 -b "${BRANCH}" "${REPO}" "${WORKSPACE}"
cd "${WORKSPACE}"
./config --prefix=$PWD/build --openssldir=/etc/ssl
make -j"$(nproc 2> /dev/null || sysctl -n hw.ncpu)"
make install_sw
