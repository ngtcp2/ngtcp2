FROM debian:12 as build

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        git g++ clang-15 make binutils autoconf automake autotools-dev libtool \
        pkg-config libev-dev libjemalloc-dev \
        ca-certificates mime-support cmake && \
    git clone --depth 1 -b v1.18.0 https://github.com/aws/aws-lc && \
    cd aws-lc && \
    cmake -Bbuild -DDISABLE_GO=ON \
        -DCMAKE_C_COMPILER=clang-15 \
        -DCMAKE_CXX_COMPILER=clang++-15 &&  \
    make -j$(nproc) -C build && cmake --install build && \
    cd .. && rm -rf aws-lc && \
    git clone --depth 1 https://github.com/ngtcp2/nghttp3 && \
    cd nghttp3 && autoreconf -i && \
    ./configure --enable-lib-only CC=clang-15 CXX=clang++-15 && \
    make -j$(nproc) && make install-strip && cd .. && rm -rf nghttp3 && \
    git clone --depth 1 https://github.com/ngtcp2/ngtcp2 && \
    cd ngtcp2 && autoreconf -i && \
    ./configure \
        CC=clang-15 \
        CXX=clang++-15 \
        LIBTOOL_LDFLAGS="-static-libtool-libs" \
        BORINGSSL_LIBS="-l:libssl.a -l:libcrypto.a" \
        LIBEV_LIBS="-l:libev.a" \
        JEMALLOC_LIBS="-l:libjemalloc.a -lm" \
        --with-boringssl && \
    make -j$(nproc) && \
    strip examples/bsslclient examples/bsslserver && \
    cp examples/bsslclient examples/bsslserver /usr/local/bin && \
    cd .. && rm -rf ngtcp2 && \
    apt-get -y purge \
        git g++ clang-15 make binutils autoconf automake autotools-dev libtool \
        pkg-config libev-dev libjemalloc-dev \
        ca-certificates cmake && \
    apt-get -y autoremove --purge && \
    rm -rf /var/log/*

FROM gcr.io/distroless/cc-debian12

COPY --from=build /usr/local/bin/bsslclient /usr/local/bin/bsslserver /usr/local/bin/
COPY --from=build /etc/mime.types /etc/

CMD ["/usr/local/bin/bsslclient"]
