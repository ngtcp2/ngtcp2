FROM debian:12 as build

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        git g++ clang-14 make binutils autoconf automake autotools-dev libtool \
        pkg-config libev-dev libjemalloc-dev \
        ca-certificates mime-support && \
    git clone --depth 1 -b v5.6.4-stable https://github.com/wolfSSL/wolfssl && \
    cd wolfssl && autoreconf -i && \
    ./configure --enable-static --enable-all --enable-quic --enable-aesni \
        --enable-harden --disable-sha224 --disable-dsa --disable-md5 && \
    make -j$(nproc) && make install-strip && cd .. && rm -rf wolfssl && \
    git clone --depth 1 https://github.com/ngtcp2/nghttp3 && \
    cd nghttp3 && autoreconf -i && \
    ./configure --enable-lib-only CC=clang-14 CXX=clang++-14 && \
    make -j$(nproc) && make install-strip && cd .. && rm -rf nghttp3 && \
    git clone --depth 1 https://github.com/ngtcp2/ngtcp2 && \
    cd ngtcp2 && autoreconf -i && \
    ./configure \
        CC=clang-14 \
        CXX=clang++-14 \
        LIBTOOL_LDFLAGS="-static-libtool-libs" \
        LIBEV_LIBS="-l:libev.a" \
        JEMALLOC_LIBS="-l:libjemalloc.a -lm" \
        --with-wolfssl && \
    make -j$(nproc) && \
    strip examples/wsslclient examples/wsslserver && \
    cp examples/wsslclient examples/wsslserver /usr/local/bin && \
    cd .. && rm -rf ngtcp2 && \
    apt-get -y purge \
        git g++ clang-14 make binutils autoconf automake autotools-dev libtool \
        pkg-config libev-dev libjemalloc-dev \
        ca-certificates && \
    apt-get -y autoremove --purge && \
    rm -rf /var/log/*

FROM gcr.io/distroless/cc-debian12

COPY --from=build /usr/local/bin/wsslclient /usr/local/bin/wsslserver /usr/local/bin/
COPY --from=build /etc/mime.types /etc/

CMD ["/usr/local/bin/wsslclient"]
