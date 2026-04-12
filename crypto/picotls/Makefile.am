# ngtcp2

# Copyright (c) 2022 ngtcp2 contributors

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
EXTRA_DIST = CMakeLists.txt

AM_CFLAGS = $(WARNCFLAGS) $(DEBUGCFLAGS) $(EXTRACFLAG)
AM_CPPFLAGS = -I$(top_srcdir)/lib/includes -I$(top_builddir)/lib/includes \
	-I$(top_srcdir)/lib -DBUILDING_NGTCP2 \
	-I$(top_srcdir)/crypto/includes -I$(top_builddir)/crypto/includes \
	-I$(top_srcdir)/crypto -I$(top_builddir)/crypto \
	@PICOTLS_CFLAGS@ @VANILLA_OPENSSL_CFLAGS@
AM_LDFLAGS = ${LIBTOOL_LDFLAGS}

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libngtcp2_crypto_picotls.pc
DISTCLEANFILES = $(pkgconfig_DATA)

lib_LIBRARIES = libngtcp2_crypto_picotls.a

libngtcp2_crypto_picotls_a_SOURCES = picotls.c ../shared.c ../shared.h

check_PROGRAMS = cryptotest

cryptotest_SOURCES = \
	../cryptotest.c \
	../shared_test.c ../shared_test.h \
	$(top_srcdir)/tests/munit/munit.c $(top_srcdir)/tests/munit/munit.h
cryptotest_CPPFLAGS = ${AM_CPPFLAGS} -I$(top_srcdir)/tests/munit
cryptotest_LDADD = \
	libngtcp2_crypto_picotls.a \
	$(top_builddir)/lib/libngtcp2.la \
	@PICOTLS_LIBS@ @VANILLA_OPENSSL_LIBS@

TESTS = cryptotest
