FROM debian:10 as build

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        git g++ make binutils autoconf automake autotools-dev libtool \
        pkg-config libev-dev libjemalloc-dev \
        ca-certificates mime-support && \
    git clone --depth 1 -b OpenSSL_1_1_1j+quic https://github.com/quictls/openssl && \
    cd openssl && ./config enable-tls1_3 --openssldir=/etc/ssl && make -j$(nproc) && make install_sw && cd .. && rm -rf openssl && \
    git clone --depth 1 https://github.com/ngtcp2/nghttp3 && \
    cd nghttp3 && autoreconf -i && \
    ./configure --enable-lib-only && \
    make -j$(nproc) && make install-strip && cd .. && rm -rf nghttp3 && \
    git clone --depth 1 https://github.com/ngtcp2/ngtcp2 && \
    cd ngtcp2 && autoreconf -i && \
    ./configure \
        LIBTOOL_LDFLAGS="-static-libtool-libs" \
        LIBS="-ldl -pthread" \
        OPENSSL_LIBS="-l:libssl.a -l:libcrypto.a" \
        LIBEV_LIBS="-l:libev.a" \
        JEMALLOC_LIBS="-l:libjemalloc.a" && \
    make -j$(nproc) && \
    strip examples/client examples/server && \
    cp examples/client examples/server /usr/local/bin && \
    cd .. && rm -rf ngtcp2 && \
    apt-get -y purge \
        git g++ make binutils autoconf automake autotools-dev libtool \
        pkg-config libev-dev libjemalloc-dev \
        ca-certificates && \
    apt-get -y autoremove --purge && \
    rm -rf /var/log/*

FROM gcr.io/distroless/cc-debian10

COPY --from=build /usr/local/bin/client /usr/local/bin/server /usr/local/bin/
COPY --from=build /etc/mime.types /etc/

CMD ["/usr/local/bin/client"]
