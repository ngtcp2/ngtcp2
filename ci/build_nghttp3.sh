#!/bin/sh -e
# build nghttp3 (for GitHub workflow)

cd ..
git clone https://github.com/ngtcp2/nghttp3
cd nghttp3
autoreconf -i
./configure --prefix=$PWD/build --enable-lib-only \
	    LDFLAGS="-fsanitize=address,undefined -fno-sanitize-recover=undefined" \
	    CPPFLAGS="-fsanitize=address,undefined -fno-sanitize-recover=undefined -g3"
make -j$(nproc) check
make install
cd ..
