#!/bin/sh -e
# build boringssl (for GitHub workflow)

git clone https://boringssl.googlesource.com/boringssl
cd boringssl
git checkout 31bad2514d21f6207f3925ba56754611c462a873
mkdir build
cd build
cmake -DCMAKE_POSITION_INDEPENDENT_CODE=ON ..
make -j"$(nproc 2> /dev/null || sysctl -n hw.ncpu)"
