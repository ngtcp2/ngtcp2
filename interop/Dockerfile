FROM ubuntu:24.04 AS build

ARG TARGETPLATFORM
ARG NGTCP2_BRANCH=main

RUN <<EOF
set -e

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    git clang-19 libclang-rt-19-dev \
    make autoconf automake autotools-dev libtool \
    pkg-config ca-certificates \
    libev-dev libjemalloc-dev media-types

case "$TARGETPLATFORM" in
    "linux/amd64")
        export WSSLFLAGS="--enable-aesni"
        ;;
    "linux/arm64")
        export WSSLFLAGS="--enable-armasm"
        ;;
esac

git clone --depth 1 -b v5.8.4-stable https://github.com/wolfSSL/wolfssl
cd wolfssl
autoreconf -i
./configure --disable-dependency-tracking --enable-static --enable-all \
    --enable-harden --enable-keylog-export --disable-ech \
    --enable-ticket-nonce-malloc --enable-mlkem $WSSLFLAGS \
    CC=clang-19 \
    CXX=clang++-19
make -j$(nproc)
make install
cd ..
rm -rf wolfssl

git clone --recursive --shallow-submodules --depth 1 \
    https://github.com/ngtcp2/nghttp3
cd nghttp3
autoreconf -i
./configure --disable-dependency-tracking --enable-lib-only \
    CC=clang-19 \
    CXX=clang++-19 \
    LDFLAGS="-fsanitize=address,undefined -fno-sanitize-recover=undefined" \
    CPPFLAGS="-fsanitize=address,undefined -fno-sanitize-recover=undefined -g3"
make -j$(nproc)
make install
cd ..
rm -rf nghttp3

git clone --recursive --shallow-submodules --depth 1 -b $NGTCP2_BRANCH \
    https://github.com/ngtcp2/ngtcp2
cd ngtcp2
autoreconf -i
./configure \
    CC=clang-19 \
    CXX=clang++-19 \
    LIBTOOL_LDFLAGS="-static-libtool-libs" \
    LDFLAGS="-fsanitize=address,undefined -fno-sanitize-recover=undefined" \
    CPPFLAGS="-fsanitize=address,undefined -fno-sanitize-recover=undefined -g3" \
    LIBEV_LIBS="-l:libev.a" \
    JEMALLOC_LIBS="-l:libjemalloc.a" \
    PKG_CONFIG_PATH=/usr/local/lib/pkgconfig \
    --disable-dependency-tracking \
    --with-wolfssl
make -j$(nproc)
cp examples/wsslclient examples/wsslserver \
   examples/h09wsslclient examples/h09wsslserver /usr/local/bin
cd ..
rm -rf ngtcp2
EOF

FROM martenseemann/quic-network-simulator-endpoint:latest

COPY --from=build --link /usr/local/bin/wsslclient /usr/local/bin/wsslserver \
    /usr/local/bin/h09wsslclient /usr/local/bin/h09wsslserver /usr/local/bin/
COPY --from=build --link /etc/mime.types /etc/
COPY --link --chmod=0775 run_endpoint.sh .

ENTRYPOINT [ "./run_endpoint.sh" ]
