FROM ubuntu:24.04 AS build

ARG TARGETPLATFORM
ARG NGTCP2_BRANCH=main

RUN <<EOF
set -e

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    git clang-19 libclang-rt-19-dev libstdc++-14-dev \
    make autoconf automake autotools-dev libtool \
    pkg-config ca-certificates \
    libev-dev media-types \
    cmake cmake-data

git clone --depth 1 -b v1.71.0 https://github.com/aws/aws-lc
cd aws-lc
cmake -Bbuild -DDISABLE_GO=ON \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_COMPILER=clang-19 \
    -DCMAKE_CXX_COMPILER=clang++-19
make -j$(nproc) -C build
cmake --install build
cd ..
rm -rf aws-lc

git clone --recursive --shallow-submodules --depth 1 -b webtransport \
    https://github.com/ngtcp2/nghttp3
cd nghttp3
autoreconf -i
./configure --disable-dependency-tracking --enable-lib-only \
    CC=clang-19 \
    CXX=clang++-19 \
    LDFLAGS="-fsanitize=address,undefined -fno-sanitize-recover=undefined" \
    CPPFLAGS="-fsanitize=address,undefined -fno-sanitize-recover=undefined -g3"
make -j$(nproc)
make install
cd ..
rm -rf nghttp3

git clone --recursive --shallow-submodules --depth 1 -b $NGTCP2_BRANCH \
    https://github.com/ngtcp2/ngtcp2
cd ngtcp2
autoreconf -i
./configure \
    CC=clang-19 \
    CXX=clang++-19 \
    LIBTOOL_LDFLAGS="-static-libtool-libs" \
    LDFLAGS="-fsanitize=address,undefined -fno-sanitize-recover=undefined" \
    CPPFLAGS="-fsanitize=address,undefined -fno-sanitize-recover=undefined -g3" \
    LIBEV_LIBS="-l:libev.a" \
    BORINGSSL_LIBS="-lssl -lcrypto" \
    BORINGSSL_CFLAGS="-I/usr/local/include" \
    PKG_CONFIG_PATH=/usr/local/lib/pkgconfig \
    --disable-dependency-tracking \
    --with-boringssl \
    --without-jemalloc
make -j$(nproc)
cp examples/bsslwtclient examples/bsslwtserver /usr/local/bin
cd ..
rm -rf ngtcp2
EOF

FROM martenseemann/quic-network-simulator-endpoint:latest

COPY --from=build --link \
    /usr/local/bin/bsslwtclient /usr/local/bin/bsslwtserver \
    /usr/local/bin/
COPY --from=build --link /etc/mime.types /etc/
COPY --link --chmod=0775 run_endpoint.sh .

ENTRYPOINT [ "./run_endpoint.sh" ]
