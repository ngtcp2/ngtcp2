# ngtcp2

# Copyright (c) 2017 ngtcp2 contributors

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

AM_CFLAGS = $(WARNCFLAGS) $(DEBUGCFLAGS)
AM_CXXFLAGS = $(WARNCXXFLAGS) $(DEBUGCFLAGS)
AM_CPPFLAGS = \
	-I$(top_srcdir)/lib/includes \
	-I$(top_builddir)/lib/includes \
	-I$(top_srcdir)/crypto/includes \
	-I$(top_srcdir)/third-party \
	@LIBEV_CFLAGS@ \
	@LIBNGHTTP3_CFLAGS@ \
	@LIBBROTLIENC_CFLAGS@ \
	@LIBBROTLIDEC_CFLAGS@ \
	@DEFS@ \
	@EXTRA_DEFS@
AM_LDFLAGS = -no-install \
	@LIBTOOL_LDFLAGS@
LDADD = $(top_builddir)/lib/libngtcp2.la \
	$(top_builddir)/third-party/libhttp-parser.la \
	@LIBEV_LIBS@ \
	@LIBNGHTTP3_LIBS@ \
	@LIBBROTLIENC_LIBS@ \
	@LIBBROTLIDEC_LIBS@

SERVER_SRCS = \
	server_base.cc server_base.h \
	tls_server_context.h \
	tls_server_session.h \
	template.h \
	debug.cc debug.h \
	util.cc util.h \
	shared.cc shared.h \
	http.cc http.h \
	network.h

CLIENT_SRCS = \
	client_base.cc client_base.h \
	tls_client_context.h \
	tls_client_session.h \
	template.h \
	debug.cc debug.h \
	util.cc util.h \
	shared.cc shared.h \
	network.h

noinst_PROGRAMS =

if ENABLE_EXAMPLE_QUICTLS
noinst_PROGRAMS += qtlsclient qtlsserver \
	qtlssimpleclient

qtlssimpleclient_CPPFLAGS = ${AM_CPPFLAGS} \
	@JEMALLOC_CFLAGS@ @OPENSSL_CFLAGS@
qtlssimpleclient_LDADD = ${LDADD} \
	$(top_builddir)/crypto/quictls/libngtcp2_crypto_quictls.la \
	@OPENSSL_LIBS@ \
	@JEMALLOC_LIBS@
qtlssimpleclient_SOURCES = simpleclient.c

qtlsclient_CPPFLAGS = ${AM_CPPFLAGS} \
	@JEMALLOC_CFLAGS@ @OPENSSL_CFLAGS@ -DWITH_EXAMPLE_QUICTLS
qtlsclient_LDADD = ${LDADD} \
	$(top_builddir)/crypto/quictls/libngtcp2_crypto_quictls.la \
	@OPENSSL_LIBS@ \
	@JEMALLOC_LIBS@
qtlsclient_SOURCES = client.cc client.h ${CLIENT_SRCS} \
	tls_client_context_quictls.cc tls_client_context_quictls.h \
	tls_client_session_quictls.cc tls_client_session_quictls.h \
	tls_session_base_quictls.cc tls_session_base_quictls.h \
	util_openssl.cc

qtlsserver_CPPFLAGS = ${qtlsclient_CPPFLAGS}
qtlsserver_LDADD = ${qtlsclient_LDADD}
qtlsserver_SOURCES = server.cc server.h ${SERVER_SRCS} \
	tls_server_context_quictls.cc tls_server_context_quictls.h \
	tls_server_session_quictls.cc tls_server_session_quictls.h \
	tls_session_base_quictls.cc tls_session_base_quictls.h \
	util_openssl.cc
endif # ENABLE_EXAMPLE_QUICTLS

if ENABLE_EXAMPLE_GNUTLS
noinst_PROGRAMS += gtlsclient gtlsserver gtlssimpleclient

gtlssimpleclient_CPPFLAGS = ${AM_CPPFLAGS} \
	@JEMALLOC_CFLAGS@ @GNUTLS_CFLAGS@
gtlssimpleclient_LDADD = ${LDADD} \
	$(top_builddir)/crypto/gnutls/libngtcp2_crypto_gnutls.la \
	@GNUTLS_LIBS@ \
	@JEMALLOC_LIBS@
gtlssimpleclient_SOURCES = gtlssimpleclient.c

gtlsclient_CPPFLAGS = ${AM_CPPFLAGS} \
	@JEMALLOC_CFLAGS@ @GNUTLS_CFLAGS@ -DWITH_EXAMPLE_GNUTLS
gtlsclient_LDADD = ${LDADD} \
	$(top_builddir)/crypto/gnutls/libngtcp2_crypto_gnutls.la \
	@GNUTLS_LIBS@ \
	@JEMALLOC_LIBS@
gtlsclient_SOURCES = client.cc client.h ${CLIENT_SRCS} \
	tls_client_context_gnutls.cc tls_client_context_gnutls.h \
	tls_client_session_gnutls.cc tls_client_session_gnutls.h \
	tls_session_base_gnutls.cc tls_session_base_gnutls.h \
	util_gnutls.cc

gtlsserver_CPPFLAGS = ${gtlsclient_CPPFLAGS}
gtlsserver_LDADD = ${gtlsclient_LDADD} \
	$(top_builddir)/crypto/gnutls/libngtcp2_crypto_gnutls.la \
	@GNUTLS_LIBS@
gtlsserver_SOURCES = server.cc server.h ${SERVER_SRCS} \
	tls_server_context_gnutls.cc tls_server_context_gnutls.h \
	tls_server_session_gnutls.cc tls_server_session_gnutls.h \
	tls_session_base_gnutls.cc tls_session_base_gnutls.h \
	util_gnutls.cc
endif # ENABLE_EXAMPLE_GNUTLS

if ENABLE_EXAMPLE_BORINGSSL
noinst_PROGRAMS += bsslclient bsslserver

bsslclient_CPPFLAGS = ${AM_CPPFLAGS} @BORINGSSL_CFLAGS@ -DWITH_EXAMPLE_BORINGSSL
bsslclient_LDADD = ${LDADD} \
	$(top_builddir)/crypto/boringssl/libngtcp2_crypto_boringssl.a \
	@BORINGSSL_LIBS@ \
	@JEMALLOC_LIBS@
bsslclient_SOURCES = client.cc client.h ${CLIENT_SRCS} \
	tls_client_context_boringssl.cc tls_client_context_boringssl.h \
	tls_client_session_boringssl.cc tls_client_session_boringssl.h \
	tls_session_base_quictls.cc tls_session_base_quictls.h \
	tls_shared_boringssl.cc tls_shared_boringssl.h \
	util_openssl.cc

bsslserver_CPPFLAGS = ${bsslclient_CPPFLAGS}
bsslserver_LDADD = ${bsslclient_LDADD}
bsslserver_SOURCES = server.cc server.h ${SERVER_SRCS} \
	tls_server_context_boringssl.cc tls_server_context_boringssl.h \
	tls_server_session_boringssl.cc tls_server_session_boringssl.h \
	tls_session_base_quictls.cc tls_session_base_quictls.h \
	tls_shared_boringssl.cc tls_shared_boringssl.h \
	util_openssl.cc
endif # ENABLE_EXAMPLE_BORINGSSL

if ENABLE_EXAMPLE_PICOTLS
noinst_PROGRAMS += ptlsclient ptlsserver

ptlsclient_CPPFLAGS = ${AM_CPPFLAGS} @PICOTLS_CFLAGS@ @VANILLA_OPENSSL_CFLAGS@ \
	-DWITH_EXAMPLE_PICOTLS
ptlsclient_LDADD = ${LDADD} \
	$(top_builddir)/crypto/picotls/libngtcp2_crypto_picotls.a \
	@PICOTLS_LIBS@ @VANILLA_OPENSSL_LIBS@ \
	@JEMALLOC_LIBS@
ptlsclient_SOURCES = client.cc client.h ${CLIENT_SRCS} \
	tls_client_context_picotls.cc tls_client_context_picotls.h \
	tls_client_session_picotls.cc tls_client_session_picotls.h \
	tls_session_base_picotls.cc tls_session_base_picotls.h \
	tls_shared_picotls.cc tls_shared_picotls.h \
	util_openssl.cc

ptlsserver_CPPFLAGS = ${ptlsclient_CPPFLAGS}
ptlsserver_LDADD = ${ptlsclient_LDADD}
ptlsserver_SOURCES = server.cc server.h ${SERVER_SRCS} \
	tls_server_context_picotls.cc tls_server_context_picotls.h \
	tls_server_session_picotls.cc tls_server_session_picotls.h \
	tls_session_base_picotls.cc tls_session_base_picotls.h \
	tls_shared_picotls.cc tls_shared_picotls.h \
	util_openssl.cc
endif # ENABLE_EXAMPLE_PICOTLS

if ENABLE_EXAMPLE_WOLFSSL
noinst_PROGRAMS += wsslclient wsslserver h09wsslclient h09wsslserver

wsslclient_CPPFLAGS = ${AM_CPPFLAGS} @WOLFSSL_CFLAGS@ -DWITH_EXAMPLE_WOLFSSL
wsslclient_LDADD = ${LDADD} \
	$(top_builddir)/crypto/wolfssl/libngtcp2_crypto_wolfssl.la \
	@WOLFSSL_LIBS@ \
	@JEMALLOC_LIBS@
wsslclient_SOURCES = client.cc client.h ${CLIENT_SRCS} \
	tls_client_context_wolfssl.cc tls_client_context_wolfssl.h \
	tls_client_session_wolfssl.cc tls_client_session_wolfssl.h \
	tls_session_base_wolfssl.cc tls_session_base_wolfssl.h \
	util_wolfssl.cc

wsslserver_CPPFLAGS = ${wsslclient_CPPFLAGS}
wsslserver_LDADD = ${wsslclient_LDADD}
wsslserver_SOURCES = server.cc server.h ${SERVER_SRCS} \
	tls_server_context_wolfssl.cc tls_server_context_wolfssl.h \
	tls_server_session_wolfssl.cc tls_server_session_wolfssl.h \
	tls_session_base_wolfssl.cc tls_session_base_wolfssl.h \
	util_wolfssl.cc

h09wsslclient_CPPFLAGS = ${wsslclient_CPPFLAGS}
h09wsslclient_LDADD = ${wsslclient_LDADD}
h09wsslclient_SOURCES = h09client.cc h09client.h ${CLIENT_SRCS} \
	tls_client_context_wolfssl.cc tls_client_context_wolfssl.h \
	tls_client_session_wolfssl.cc tls_client_session_wolfssl.h \
	tls_session_base_wolfssl.cc tls_session_base_wolfssl.h \
	util_wolfssl.cc

h09wsslserver_CPPFLAGS = ${wsslclient_CPPFLAGS}
h09wsslserver_LDADD = ${wsslclient_LDADD}
h09wsslserver_SOURCES = h09server.cc h09server.h ${SERVER_SRCS} \
	tls_server_context_wolfssl.cc tls_server_context_wolfssl.h \
	tls_server_session_wolfssl.cc tls_server_session_wolfssl.h \
	tls_session_base_wolfssl.cc tls_session_base_wolfssl.h \
	util_wolfssl.cc
endif # ENABLE_EXAMPLE_WOLFSSL

check_PROGRAMS = examplestest
examplestest_SOURCES = examplestest.cc \
	util_test.cc util_test.h util.cc util.h \
	$(top_srcdir)/tests/munit/munit.c $(top_srcdir)/tests/munit/munit.h
examplestest_CPPFLAGS = ${AM_CPPFLAGS} -I$(top_srcdir)/tests/munit \
	@JEMALLOC_CFLAGS@
examplestest_LDADD = ${LDADD} @JEMALLOC_LIBS@

TESTS = examplestest
