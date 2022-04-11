#!/bin/sh -e
# build boringssl (for GitHub workflow)

git clone https://boringssl.googlesource.com/boringssl
cd boringssl
git checkout 27ffcc6e19bbafddf1b59ec0bc6df2904de7eb2c
mkdir build
cd build
cmake -DCMAKE_POSITION_INDEPENDENT_CODE=ON ..
make -j"$(nproc 2> /dev/null || sysctl -n hw.ncpu)"
