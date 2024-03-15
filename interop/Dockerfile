FROM martenseemann/quic-network-simulator-endpoint:latest

ARG NGTCP2_BRANCH=main

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        git gcc clang-12 make binutils autoconf automake autotools-dev libtool \
        pkg-config libev-dev libjemalloc-dev \
        libev4 libjemalloc2 ca-certificates mime-support \
        llvm-12 libasan5 libubsan1 && \
    git clone --depth 1 -b v5.6.6-stable https://github.com/wolfSSL/wolfssl && \
    cd wolfssl && autoreconf -i && \
    ./configure --enable-all --enable-aesni --enable-harden \
        --enable-keylog-export --disable-ech && \
    make -j$(nproc) && make install && cd .. && rm -rf wolfssl && \
    git clone --recursive --shallow-submodules --depth 1 https://github.com/ngtcp2/nghttp3 && \
    cd nghttp3 && \
    autoreconf -i && \
    ./configure --enable-lib-only \
        CC=clang-12 \
        CXX=clang++-12 \
        LDFLAGS="-fsanitize=address,undefined -fno-sanitize-recover=undefined" \
        CPPFLAGS="-fsanitize=address,undefined -fno-sanitize-recover=undefined -g3" && \
    make -j$(nproc) && make install && cd .. && rm -rf nghttp3 && \
    git clone --recursive --shallow-submodules --depth 1 -b $NGTCP2_BRANCH https://github.com/ngtcp2/ngtcp2 && \
    cd ngtcp2 && \
    autoreconf -i && \
    ./configure \
        CC=clang-12 \
        CXX=clang++-12 \
        LDFLAGS="-fsanitize=address,undefined -fno-sanitize-recover=undefined" \
        CPPFLAGS="-fsanitize=address,undefined -fno-sanitize-recover=undefined -g3" \
        --with-wolfssl && \
    make -j$(nproc) && make install && \
    cp examples/wsslserver examples/wsslclient examples/h09wsslserver examples/h09wsslclient /usr/local/bin && \
    cd .. && \
    rm -rf ngtcp2 && \
    rm -rf /usr/local/lib/libssl.so /usr/local/lib/libcrypto.so /usr/local/lib/libssl.a /usr/local/lib/libcrypto.a /usr/local/lib/pkgconfig/*ssl.pc /usr/local/include/wolfssl/* && \
    apt-get -y purge git g++ clang-12 make binutils autoconf automake \
        autotools-dev libtool pkg-config \
        libev-dev libjemalloc-dev && \
    apt-get -y autoremove --purge && \
    rm -rf /var/log/*

COPY --link run_endpoint.sh .
RUN chmod +x run_endpoint.sh
ENTRYPOINT [ "./run_endpoint.sh" ]
