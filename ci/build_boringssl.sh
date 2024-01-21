#!/bin/sh -e
# build boringssl (for GitHub workflow)

git clone https://boringssl.googlesource.com/boringssl
cd boringssl
git checkout "${BORINGSSL_VERSION}"
cmake -B build -DCMAKE_POSITION_INDEPENDENT_CODE=ON
make -j"$(nproc 2> /dev/null || sysctl -n hw.ncpu)" -C build
