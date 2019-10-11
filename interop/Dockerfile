FROM martenseemann/quic-network-simulator-endpoint:latest

RUN apt-get update && \
    apt-get install -y \
        git g++ make binutils autoconf automake autotools-dev libtool \
	pkg-config libev-dev libjemalloc-dev \
        libev4 libjemalloc2 ca-certificates mime-support && \
    git clone --depth 1 -b openssl-quic-draft-23 https://github.com/tatsuhiro-t/openssl && \
    cd openssl && ./config enable-tls1_3 --openssldir=/etc/ssl && make -j$(nproc) && make install_sw && cd .. && rm -rf openssl && \
    git clone --depth 1 https://github.com/ngtcp2/nghttp3 && \
    cd nghttp3 && autoreconf -i && \
    ./configure --enable-lib-only && \
    make -j$(nproc) && make install-strip && cd .. && rm -rf nghttp3 && \
    git clone --depth 1 -b interop https://github.com/ngtcp2/ngtcp2 && \
    cd ngtcp2 && autoreconf -i && \
    ./configure && \
    make -j$(nproc) && make install-strip && cp examples/server examples/client /usr/local/bin && cd .. && rm -rf ngtcp2 && \
    strip /usr/local/lib/*.so.*.* /usr/local/lib/engines-*/*.so && \
    rm -rf /usr/local/lib/libssl.so /usr/local/lib/libcrypto.so /usr/local/lib/libssl.a /usr/local/lib/libcrypto.a /usr/local/lib/pkgconfig/*ssl.pc /usr/local/include/openssl/* && \
    apt-get -y purge git g++ make binutils autoconf automake autotools-dev libtool pkg-config \
        libev-dev libjemalloc-dev && \
    apt-get -y autoremove --purge && \
    rm -rf /var/log/*

COPY run_endpoint.sh .
COPY server.key server.crt /etc/ngtcp2/
RUN chmod +x run_endpoint.sh
ENTRYPOINT [ "./run_endpoint.sh" ]
