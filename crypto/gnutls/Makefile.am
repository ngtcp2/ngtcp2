# ngtcp2

# Copyright (c) 2020 ngtcp2 contributors

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
	@GNUTLS_CFLAGS@
AM_LDFLAGS = ${LIBTOOL_LDFLAGS}

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libngtcp2_crypto_gnutls.pc
DISTCLEANFILES = $(pkgconfig_DATA)

lib_LTLIBRARIES = libngtcp2_crypto_gnutls.la

libngtcp2_crypto_gnutls_la_SOURCES = gnutls.c ../shared.c ../shared.h
libngtcp2_crypto_gnutls_la_LDFLAGS = -no-undefined \
	-version-info $(CRYPTO_GNUTLS_LT_CURRENT):$(CRYPTO_GNUTLS_LT_REVISION):$(CRYPTO_GNUTLS_LT_AGE)
libngtcp2_crypto_gnutls_la_LIBADD = $(top_builddir)/lib/libngtcp2.la \
	@GNUTLS_LIBS@
