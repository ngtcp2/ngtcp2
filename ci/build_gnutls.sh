#!/bin/sh -e
# build gnutls (for GitHub workflow)

curl -LO https://ftp.gnu.org/gnu/nettle/nettle-3.6.tar.gz
tar xf nettle-3.6.tar.gz
cd nettle-3.6
./configure --prefix=$PWD/build
make
make install
cd ..

curl -LO https://www.gnupg.org/ftp/gcrypt/gnutls/v3.7/gnutls-3.7.0.tar.xz
tar xf gnutls-3.7.0.tar.xz
cd gnutls-3.7.0
./configure --prefix=$PWD/build \
	    --with-included-unistring \
	    --with-included-libtasn1 \
	    --without-p11-kit \
	    PKG_CONFIG_PATH="$PWD/../nettle-3.6/build/lib64/pkgconfig"
make -j$(nproc)
make install
