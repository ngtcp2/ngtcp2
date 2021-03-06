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

AM_CFLAGS = $(WARNCFLAGS) $(DEBUGCFLAGS)
AM_CXXFLAGS = $(WARNCXXFLAGS) $(DEBUGCFLAGS)
AM_CPPFLAGS = \
	-I$(top_srcdir)/lib/includes \
	-I$(top_builddir)/lib/includes \
	-I$(top_srcdir)/crypto/includes \
	-I$(top_srcdir)/third-party \
	@LIBEV_CFLAGS@ \
	@LIBNGHTTP3_CFLAGS@ \
	@DEFS@ \
	@EXTRA_DEFS@
AM_LDFLAGS = -no-install \
	@LIBTOOL_LDFLAGS@
LDADD = $(top_builddir)/lib/libngtcp2.la \
	$(top_builddir)/third-party/libhttp-parser.la \
	@LIBEV_LIBS@ \
	@LIBNGHTTP3_LIBS@

SERVER_SRCS = \
	server_base.cc server_base.h \
	tls_server_context.h \
	template.h \
	debug.cc debug.h \
	util.cc util.h \
	shared.cc shared.h \
	http.cc http.h

CLIENT_SRCS = \
	client_base.cc client_base.h \
	tls_client_context.h \
	template.h \
	debug.cc debug.h \
	util.cc util.h \
	shared.cc shared.h

noinst_PROGRAMS =

if ENABLE_EXAMPLE_OPENSSL
noinst_PROGRAMS += client server h09client h09server perfserver

client_CPPFLAGS = ${AM_CPPFLAGS} \
	@JEMALLOC_CFLAGS@ @OPENSSL_CFLAGS@ -DWITH_EXAMPLE_OPENSSL
client_LDADD = ${LDADD} \
	$(top_builddir)/crypto/openssl/libngtcp2_crypto_openssl.la \
	@OPENSSL_LIBS@ \
	@JEMALLOC_LIBS@
client_SOURCES = client.cc client.h ${CLIENT_SRCS} \
	tls_client_context_openssl.cc tls_client_context_openssl.h \
	tls_client_session_openssl.cc tls_client_session_openssl.h \
	tls_session_base_openssl.cc tls_session_base_openssl.h \
	util_openssl.cc

server_CPPFLAGS = ${client_CPPFLAGS}
server_LDADD = ${client_LDADD}
server_SOURCES = server.cc server.h ${SERVER_SRCS} \
	tls_server_context_openssl.cc tls_server_context_openssl_h \
	tls_server_session_openssl.cc tls_server_session_openssl.h \
	tls_session_base_openssl.cc tls_session_base_openssl.h \
	util_openssl.cc util_aead_openssl.cc

h09client_CPPFLAGS = ${client_CPPFLAGS}
h09client_LDADD = ${client_LDADD}
h09client_SOURCES = h09client.cc h09client.h ${CLIENT_SRCS} \
	tls_client_context_openssl.cc tls_client_context_openssl.h \
	tls_client_session_openssl.cc tls_client_session_openssl.h \
	tls_session_base_openssl.cc tls_session_base_openssl.h \
	util_openssl.cc

h09server_CPPFLAGS = ${client_CPPFLAGS}
h09server_LDADD = ${client_LDADD}
h09server_SOURCES = h09server.cc h09server.h ${SERVER_SRCS} \
	tls_server_context_openssl.cc tls_server_context_openssl.h \
	tls_server_session_openssl.cc tls_server_session_openssl.h \
	tls_session_base_openssl.cc tls_session_base_openssl.h \
	util_openssl.cc util_aead_openssl.cc

perfserver_CPPFLAGS = ${client_CPPFLAGS}
perfserver_LDADD = ${client_LDADD}
perfserver_SOURCES = perfserver.cc perfserver.h ${SERVER_SRCS} \
	tls_server_context_openssl.cc tls_server_context_openssl.h \
	tls_server_session_openssl.cc tls_server_session_openssl.h \
	tls_session_base_openssl.cc tls_session_base_openssl.h \
	util_openssl.cc util_aead_openssl.cc
endif # ENABLE_EXAMPLE_OPENSSL

if ENABLE_EXAMPLE_GNUTLS
noinst_PROGRAMS += gtlsclient gtlsserver

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
	$(top_builddir)/crypto/boringssl/libngtcp2_crypto_boringssl.la \
	@BORINGSSL_LIBS@
bsslclient_SOURCES = client.cc client.h ${CLIENT_SRCS} \
	tls_client_context_boringssl.cc tls_client_context_boringssl.h \
	tls_client_session_boringssl.cc tls_client_session_boringssl.h \
	tls_session_base_openssl.cc tls_session_base_openssl.h \
	util_openssl.cc

bsslserver_CPPFLAGS = ${bsslclient_CPPFLAGS}
bsslserver_LDADD = ${bsslclient_LDADD}
bsslserver_SOURCES = server.cc server.h ${SERVER_SRCS} \
	tls_server_context_boringssl.cc tls_server_context_boringssl_h \
	tls_server_session_boringssl.cc tls_server_session_boringssl.h \
	tls_session_base_openssl.cc tls_session_base_openssl.h \
	util_openssl.cc util_aead_boringssl.cc
endif # ENABLE_EXAMPLE_BORINGSSL

if HAVE_CUNIT
check_PROGRAMS = examplestest
examplestest_SOURCES = examplestest.cc \
	util_test.cc util_test.h util.cc util.h
examplestest_CPPFLAGS = ${AM_CPPFLAGS} @JEMALLOC_CFLAGS@
examplestest_LDADD = ${LDADD} @CUNIT_LIBS@ @JEMALLOC_LIBS@

TESTS = examplestest
endif # HAVE_CUNIT
