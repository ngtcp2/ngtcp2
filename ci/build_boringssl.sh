#!/bin/sh -e
# build boringssl (for GitHub workflow)

mkdir boringssl
cd boringssl
git init
git remote add origin https://boringssl.googlesource.com/boringssl
git fetch origin --depth 1 "${BORINGSSL_VERSION}"
git checkout "${BORINGSSL_VERSION}"
cmake -B build -DCMAKE_POSITION_INDEPENDENT_CODE=ON
make -j"$(nproc 2> /dev/null || sysctl -n hw.ncpu)" -C build
