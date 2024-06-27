FROM --platform=$BUILDPLATFORM tonistiigi/xx AS xx

FROM --platform=$BUILDPLATFORM ubuntu:22.04 AS build

COPY --from=xx --link / /

ARG TARGETPLATFORM

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive \
        apt-get install -y --no-install-recommends \
        git clang-15 make autoconf automake autotools-dev libtool dpkg-dev \
        pkg-config ca-certificates && \
    DEBIAN_FRONTEND=noninteractive \
        xx-apt-get install -y --no-install-recommends \
        gcc-12 g++-12 libc6-dev binutils \
        libev-dev libjemalloc-dev && \
    ln -s /usr/bin/clang-15 /usr/bin/clang && \
    ln -s /usr/bin/clang++-15 /usr/bin/clang++

RUN if [ "$TARGETPLATFORM" = "linux/amd64" ]; then export WSSLFLAGS="--enable-aesni"; fi && \
    if [ "$TARGETPLATFORM" = "linux/arm64" ]; then export WSSLFLAGS="--enable-armasm"; fi && \
    git clone --depth 1 -b v5.7.0-stable https://github.com/wolfSSL/wolfssl && \
    cd wolfssl && autoreconf -i && \
    ./configure --disable-dependency-tracking --enable-static --enable-all \
        --enable-harden --enable-keylog-export --disable-ech $WSSLFLAGS \
        --host=$(xx-clang --print-target-triple) \
        CC=$(xx-info)-gcc-12 \
        CXX=$(xx-info)-g++-12 && \
    make -j$(nproc) && make install && cd .. && rm -rf wolfssl

RUN git clone --recursive --shallow-submodules --depth 1 https://github.com/ngtcp2/nghttp3 && \
    cd nghttp3 && \
    autoreconf -i && \
    ./configure --disable-dependency-tracking --enable-lib-only \
        --host=$(xx-clang --print-target-triple) \
        CC=$(xx-info)-gcc-12 \
        CXX=$(xx-info)-g++-12 \
        LDFLAGS="-fsanitize=address,undefined -fno-sanitize-recover=undefined" \
        CPPFLAGS="-fsanitize=address,undefined -fno-sanitize-recover=undefined -g3" && \
    make -j$(nproc) && make install && cd .. && rm -rf nghttp3

ARG NGTCP2_BRANCH=main

RUN git clone --recursive --shallow-submodules --depth 1 -b $NGTCP2_BRANCH https://github.com/ngtcp2/ngtcp2 && \
    cd ngtcp2 && \
    autoreconf -i && \
    ./configure \
        --host=$(xx-clang --print-target-triple) \
        CC=$(xx-info)-gcc-12 \
        CXX=$(xx-info)-g++-12 \
        LIBTOOL_LDFLAGS="-static-libtool-libs" \
        LDFLAGS="-fsanitize=address,undefined -fno-sanitize-recover=undefined -static-libgcc -static-libstdc++ -static-libasan -static-libubsan" \
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

FROM ghcr.io/tatsuhiro-t/quic-network-simulator-endpoint:latest

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        mime-support

COPY --from=build --link /usr/local/bin/wsslclient /usr/local/bin/wsslserver \
    /usr/local/bin/h09wsslclient /usr/local/bin/h09wsslserver /usr/local/bin/
COPY --link --chmod=0775 run_endpoint.sh .

ENTRYPOINT [ "./run_endpoint.sh" ]
