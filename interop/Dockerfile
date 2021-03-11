FROM martenseemann/quic-network-simulator-endpoint:latest

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        git g++ make binutils autoconf automake autotools-dev libtool \
        pkg-config libev-dev libjemalloc-dev \
        libev4 libjemalloc2 ca-certificates mime-support \
        libasan5 libubsan1 && \
    git clone --depth 1 -b OpenSSL_1_1_1j+quic https://github.com/quictls/openssl && \
    cd openssl && ./config enable-tls1_3 --openssldir=/etc/ssl && make -j$(nproc) && make install_sw && cd .. && rm -rf openssl && \
    git clone --depth 1 https://github.com/ngtcp2/nghttp3 && \
    cd nghttp3 && autoreconf -i && \
    ./configure --enable-lib-only \
        LDFLAGS="-fsanitize=address,undefined -fno-sanitize-recover=undefined" \
        CPPFLAGS="-fsanitize=address,undefined -fno-sanitize-recover=undefined -g3" && \
    make -j$(nproc) && make install && cd .. && rm -rf nghttp3 && \
    git clone --depth 1 https://github.com/ngtcp2/ngtcp2 && \
    cd ngtcp2 && autoreconf -i && \
    ./configure \
        CXXFLAGS=-DNGTCP2_ENABLE_UDP_GSO=0 \
        LDFLAGS="-fsanitize=address,undefined -fno-sanitize-recover=undefined" \
        CPPFLAGS="-fsanitize=address,undefined -fno-sanitize-recover=undefined -g3" && \
    make -j$(nproc) && make install && \
    cp examples/server examples/client examples/h09server examples/h09client /usr/local/bin && \
    cd .. && \
    rm -rf ngtcp2 && \
    rm -rf /usr/local/lib/libssl.so /usr/local/lib/libcrypto.so /usr/local/lib/libssl.a /usr/local/lib/libcrypto.a /usr/local/lib/pkgconfig/*ssl.pc /usr/local/include/openssl/* && \
    apt-get -y purge git g++ make binutils autoconf automake autotools-dev libtool pkg-config \
        libev-dev libjemalloc-dev && \
    apt-get -y autoremove --purge && \
    rm -rf /var/log/*

COPY run_endpoint.sh .
RUN chmod +x run_endpoint.sh
ENTRYPOINT [ "./run_endpoint.sh" ]
