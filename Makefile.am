# ngtcp2

# Copyright (c) 2016 ngtcp2 contributors

# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:

# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
SUBDIRS = lib tests doc

if HAVE_CRYPTO
SUBDIRS += crypto
endif

if ENABLE_EXAMPLES
SUBDIRS += third-party examples
endif

dist_doc_DATA = README.rst

ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = \
	cmakeconfig.h.in \
	CMakeLists.txt \
	CMakeOptions.txt \
	cmake/FindCUnit.cmake \
	cmake/FindLibev.cmake \
	cmake/FindLibnghttp3.cmake \
	cmake/Findwolfssl.cmake \
	cmake/PickyWarningsC.cmake \
	cmake/PickyWarningsCXX.cmake \
	cmake/Version.cmake

# Format source files using clang-format.  Don't format source files
# under third-party directory since we are not responsible for their
# coding style.
clang-format:
	CLANGFORMAT=`git config --get clangformat.binary`; \
	test -z $${CLANGFORMAT} && CLANGFORMAT="clang-format"; \
	$${CLANGFORMAT} -i lib/*.{c,h} tests/*.{c,h} lib/includes/ngtcp2/*.h \
	crypto/*.{c,h} \
	crypto/quictls/*.c crypto/gnutls/*.c crypto/boringssl/*.c \
	crypto/wolfssl/*.c \
	crypto/includes/ngtcp2/*.h \
	examples/*.{cc,c,h} \
	fuzz/*.cc
