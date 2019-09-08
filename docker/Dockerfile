FROM k8s.gcr.io/debian-base-amd64:1.0.0

RUN /usr/local/bin/clean-install \
        git g++ make binutils autoconf automake autotools-dev libtool \
	pkg-config libev-dev libjemalloc-dev \
        libev4 libjemalloc1 ca-certificates && \
    git clone --depth 1 -b openssl-quic-draft-22 https://github.com/tatsuhiro-t/openssl && \
    cd openssl && ./config enable-tls1_3 --openssldir=/etc/ssl && make -j$(nproc) && make install_sw && cd .. && rm -rf openssl && \
    git clone --depth 1 https://github.com/ngtcp2/nghttp3 && \
    cd nghttp3 && autoreconf -i && \
    ./configure --enable-lib-only && \
    make -j$(nproc) && make install-strip && cd .. && rm -rf nghttp3 && \
    git clone --depth 1 -b draft-22 https://github.com/ngtcp2/ngtcp2 && \
    cd ngtcp2 && autoreconf -i && \
    ./configure && \
    make -j$(nproc) && make install-strip && cp examples/server examples/client /usr/local/bin && cd .. && rm -rf ngtcp2 && \
    strip /usr/local/lib/*.so.*.* /usr/local/lib/engines-*/*.so && \
    rm -rf /usr/local/lib/libssl.so /usr/local/lib/libcrypto.so /usr/local/lib/libssl.a /usr/local/lib/libcrypto.a /usr/local/lib/pkgconfig/*ssl.pc /usr/local/include/openssl/* && \
    apt-get -y purge git g++ make binutils autoconf automake autotools-dev libtool pkg-config \
        libev-dev libjemalloc-dev && \
    apt-get -y autoremove --purge && \
    rm -rf /var/log/*
