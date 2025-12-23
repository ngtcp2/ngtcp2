FROM debian:13 as build

ARG NGTCP2_BRANCH=main

RUN <<EOF
set -e

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    git clang-19 make binutils autoconf automake autotools-dev libtool \
    pkg-config libev-dev libjemalloc-dev \
    ca-certificates media-types

git clone --depth 1 -b v5.8.4-stable https://github.com/wolfSSL/wolfssl
cd wolfssl
autoreconf -i
./configure --disable-dependency-tracking --enable-static --enable-all \
    --enable-aesni --enable-harden --enable-keylog-export --disable-ech \
    --enable-mlkem \
    CC=clang-19 CXX=clang++-19
make -j$(nproc)
make install-strip
cd ..
rm -rf wolfssl

git clone --recursive --shallow-submodules --depth 1 \
    https://github.com/ngtcp2/nghttp3
cd nghttp3
autoreconf -i
./configure --disable-dependency-tracking --enable-lib-only \
    CC=clang-19 CXX=clang++-19
make -j$(nproc)
make install-strip
cd ..
rm -rf nghttp3

git clone --recursive --shallow-submodules --depth 1 -b $NGTCP2_BRANCH \
    https://github.com/ngtcp2/ngtcp2
cd ngtcp2
autoreconf -i
./configure \
    CC=clang-19 \
    CXX=clang++-19 \
    LDFLAGS="-static-libgcc -static-libstdc++" \
    LIBTOOL_LDFLAGS="-static-libtool-libs" \
    LIBEV_LIBS="-l:libev.a" \
    JEMALLOC_LIBS="-l:libjemalloc.a -lm" \
    --disable-dependency-tracking \
    --with-wolfssl
make -j$(nproc)
strip examples/wsslclient examples/wsslserver
cp examples/wsslclient examples/wsslserver /usr/local/bin
cd ..
rm -rf ngtcp2

apt-get -y purge \
    git clang-19 make binutils autoconf automake autotools-dev libtool \
    pkg-config libev-dev libjemalloc-dev \
    ca-certificates
apt-get -y autoremove --purge
rm -rf /var/log/*
EOF

FROM gcr.io/distroless/base-nossl-debian13

COPY --from=build --link /usr/local/bin/wsslclient /usr/local/bin/wsslserver \
    /usr/local/bin/
COPY --from=build --link /etc/mime.types /etc/

CMD ["/usr/local/bin/wsslclient"]
