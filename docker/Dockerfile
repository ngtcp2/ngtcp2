FROM debian:12 as build

ARG NGTCP2_BRANCH=main

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        git g++ clang-15 make binutils autoconf automake autotools-dev libtool \
        pkg-config libev-dev libjemalloc-dev cmake cmake-data \
        ca-certificates mime-support && \
    git clone --depth 1 -b v5.6.6-stable https://github.com/wolfSSL/wolfssl && \
    cd wolfssl && autoreconf -i && \
    ./configure --enable-static --enable-all --enable-aesni \
        --enable-harden --enable-keylog-export && \
    make -j$(nproc) && make install-strip && cd .. && rm -rf wolfssl && \
    git clone --depth 1 -b 10.2.1 https://github.com/fmtlib/fmt && \
    cd fmt && cmake -B build -DCMAKE_CXX_COMPILER=clang++-15 && \
    make -j$(nproc) -C build && cmake --install build && \
    cd .. && rm -rf fmt && \
    git clone --depth 1 https://github.com/ngtcp2/nghttp3 && \
    cd nghttp3 && autoreconf -i && \
    ./configure --enable-lib-only CC=clang-15 CXX=clang++-15 && \
    make -j$(nproc) && make install-strip && cd .. && rm -rf nghttp3 && \
    git clone --depth 1 -b $NGTCP2_BRANCH https://github.com/ngtcp2/ngtcp2 && \
    cd ngtcp2 && autoreconf -i && \
    ./configure \
        CC=clang-15 \
        CXX=clang++-15 \
        LIBTOOL_LDFLAGS="-static-libtool-libs" \
        LIBEV_LIBS="-l:libev.a" \
        FMT_LIBS="-l:libfmt.a" \
        JEMALLOC_LIBS="-l:libjemalloc.a -lm" \
        --with-wolfssl && \
    make -j$(nproc) && \
    strip examples/wsslclient examples/wsslserver && \
    cp examples/wsslclient examples/wsslserver /usr/local/bin && \
    cd .. && rm -rf ngtcp2 && \
    apt-get -y purge \
        git g++ clang-15 make binutils autoconf automake autotools-dev libtool \
        pkg-config libev-dev libjemalloc-dev \
        ca-certificates && \
    apt-get -y autoremove --purge && \
    rm -rf /var/log/*

FROM gcr.io/distroless/cc-debian12

COPY --from=build /usr/local/bin/wsslclient /usr/local/bin/wsslserver /usr/local/bin/
COPY --from=build /etc/mime.types /etc/

CMD ["/usr/local/bin/wsslclient"]
