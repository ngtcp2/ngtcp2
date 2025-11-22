FROM ubuntu:24.04 AS build

ARG TARGETPLATFORM

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive \
        apt-get install -y --no-install-recommends \
        git clang-19 libclang-rt-19-dev \
        make autoconf automake autotools-dev libtool \
        pkg-config ca-certificates \
        libev-dev libjemalloc-dev

RUN if [ "$TARGETPLATFORM" = "linux/amd64" ]; then export WSSLFLAGS="--enable-aesni"; fi && \
    if [ "$TARGETPLATFORM" = "linux/arm64" ]; then export WSSLFLAGS="--enable-armasm"; fi && \
    git clone --depth 1 -b v5.8.4-stable https://github.com/wolfSSL/wolfssl && \
    cd wolfssl && autoreconf -i && \
    ./configure --disable-dependency-tracking --enable-static --enable-all \
        --enable-harden --enable-keylog-export --disable-ech \
        --enable-ticket-nonce-malloc --enable-mlkem $WSSLFLAGS \
        CC=clang-19 \
        CXX=clang++-19 && \
    make -j$(nproc) && make install && cd .. && rm -rf wolfssl

RUN git clone --recursive --shallow-submodules --depth 1 https://github.com/ngtcp2/nghttp3 && \
    cd nghttp3 && \
    autoreconf -i && \
    ./configure --disable-dependency-tracking --enable-lib-only \
        CC=clang-19 \
        CXX=clang++-19 \
        LDFLAGS="-fsanitize=address,undefined -fno-sanitize-recover=undefined" \
        CPPFLAGS="-fsanitize=address,undefined -fno-sanitize-recover=undefined -g3" && \
    make -j$(nproc) && make install && cd .. && rm -rf nghttp3

ARG NGTCP2_BRANCH=main

RUN git clone --recursive --shallow-submodules --depth 1 -b $NGTCP2_BRANCH https://github.com/ngtcp2/ngtcp2 && \
    cd ngtcp2 && \
    autoreconf -i && \
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
        --with-wolfssl && \
    make -j$(nproc) && \
    cp examples/wsslclient examples/wsslserver \
        examples/h09wsslclient examples/h09wsslserver /usr/local/bin && \
    rm -rf ngtcp2

FROM martenseemann/quic-network-simulator-endpoint:latest

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        media-types

COPY --from=build --link /usr/local/bin/wsslclient /usr/local/bin/wsslserver \
    /usr/local/bin/h09wsslclient /usr/local/bin/h09wsslserver /usr/local/bin/
COPY --link --chmod=0775 run_endpoint.sh .

ENTRYPOINT [ "./run_endpoint.sh" ]
