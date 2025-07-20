#!/bin/sh -e
# wolfssl (for GitHub workflow)

git clone --depth 1 -b "${WOLFSSL_VERSION}" https://github.com/wolfSSL/wolfssl
cd wolfssl
autoreconf -i
./configure --disable-dependency-tracking --prefix=$PWD/build --enable-all \
            --enable-harden --enable-keylog-export --disable-ech \
            --enable-mlkem \
            $EXTRA_CONFIGURE_FLAGS
make -j"$(nproc 2> /dev/null || sysctl -n hw.ncpu)"
make install
