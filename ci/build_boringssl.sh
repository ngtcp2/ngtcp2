#!/bin/sh -e
# build boringssl (for GitHub workflow)

git clone https://boringssl.googlesource.com/boringssl
cd boringssl
git checkout b09f283a030efc650cfcb3476932626c5000b921
mkdir build
cd build
CFLAGS=-fpic CXXFLAGS=-fpic cmake ..
make -j$(nproc)
