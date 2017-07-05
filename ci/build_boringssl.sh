#!/bin/sh
#build last boringssl master (for Travis)

cd ..
git clone --depth 1 https://boringssl.googlesource.com/boringssl
cd boringssl
mkdir build
cd build
cmake ..
make -j$(nproc)
cd ../../
