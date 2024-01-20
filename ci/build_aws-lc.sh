#!/bin/sh -e
# build aws-lc (for GitHub workflow)

git clone --depth 1 -b "${AWSLC_VERSION}" https://github.com/aws/aws-lc
cd aws-lc
cmake -B build -DDISABLE_GO=ON
make -j"$(nproc 2> /dev/null || sysctl -n hw.ncpu)" -C build
