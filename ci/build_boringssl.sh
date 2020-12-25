#!/bin/sh -e
# build boringssl (for GitHub workflow)

cd ..
git clone https://boringssl.googlesource.com/boringssl
cd boringssl
git checkout 78f15a6aa9f11ab7cff736f920c4858cc38264fb
mkdir build
cd build
CFLAGS=-fpic CXXFLAGS=-fpic cmake ..
make -j$(nproc)
cd ..
