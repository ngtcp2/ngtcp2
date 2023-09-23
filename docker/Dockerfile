FROM debian:12 as build

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        git g++ clang-14 make binutils autoconf automake autotools-dev libtool \
        pkg-config libev-dev libjemalloc-dev \
        ca-certificates mime-support && \
    git clone --depth 1 -b OpenSSL_1_1_1w+quic https://github.com/quictls/openssl && \
    cd openssl && ./config --openssldir=/etc/ssl && make -j$(nproc) && make install_sw && cd .. && rm -rf openssl && \
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
        OPENSSL_LIBS="-l:libssl.a -l:libcrypto.a -ldl -pthread" \
        LIBEV_LIBS="-l:libev.a" \
        JEMALLOC_LIBS="-l:libjemalloc.a -lm" && \
    make -j$(nproc) && \
    strip examples/qtlsclient examples/qtlsserver && \
    cp examples/qtlsclient examples/qtlsserver /usr/local/bin && \
    cd .. && rm -rf ngtcp2 && \
    apt-get -y purge \
        git g++ clang-14 make binutils autoconf automake autotools-dev libtool \
        pkg-config libev-dev libjemalloc-dev \
        ca-certificates && \
    apt-get -y autoremove --purge && \
    rm -rf /var/log/*

FROM gcr.io/distroless/cc-debian12

COPY --from=build /usr/local/bin/qtlsclient /usr/local/bin/qtlsserver /usr/local/bin/
COPY --from=build /etc/mime.types /etc/

CMD ["/usr/local/bin/qtlsclient"]
