#!/bin/sh -e
# build boringssl (for GitHub workflow)

git clone https://boringssl.googlesource.com/boringssl
cd boringssl
git checkout b2536a2c6234496ef609e7c909936bbf828dac6d
mkdir build
cd build
cmake -DCMAKE_POSITION_INDEPENDENT_CODE=ON ..
make -j"$(nproc 2> /dev/null || sysctl -n hw.ncpu)"
