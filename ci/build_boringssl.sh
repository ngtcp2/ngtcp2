#!/bin/sh -e
# build boringssl (for GitHub workflow)

git clone https://boringssl.googlesource.com/boringssl
cd boringssl
git checkout f6ef1c560ae5af51e2df5d8d2175bed207b28b8f
mkdir build
cd build
cmake -DCMAKE_POSITION_INDEPENDENT_CODE=ON ..
make -j$(nproc)
