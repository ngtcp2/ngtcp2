# ngtcp2

# Copyright (c) 2016 ngtcp2 contributors
# Copyright (c) 2012 nghttp2 contributors

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

if HAVE_CUNIT

check_PROGRAMS = main

OBJECTS = \
	main.c \
	ngtcp2_pkt_test.c \
	ngtcp2_range_test.c \
	ngtcp2_rob_test.c \
	ngtcp2_acktr_test.c \
	ngtcp2_map_test.c \
	ngtcp2_crypto_test.c \
	ngtcp2_rtb_test.c \
	ngtcp2_idtr_test.c \
	ngtcp2_conn_test.c \
	ngtcp2_ringbuf_test.c \
	ngtcp2_conv_test.c \
	ngtcp2_ksl_test.c \
	ngtcp2_gaptr_test.c \
	ngtcp2_vec_test.c \
	ngtcp2_strm_test.c \
	ngtcp2_pv_test.c \
	ngtcp2_pmtud_test.c \
	ngtcp2_str_test.c \
	ngtcp2_tstamp_test.c \
	ngtcp2_conversion_test.c \
	ngtcp2_cc_test.c \
	ngtcp2_test_helper.c
HFILES= \
	ngtcp2_pkt_test.h \
	ngtcp2_range_test.h \
	ngtcp2_rob_test.h \
	ngtcp2_acktr_test.h \
	ngtcp2_map_test.h \
	ngtcp2_crypto_test.h \
	ngtcp2_rtb_test.h \
	ngtcp2_idtr_test.h \
	ngtcp2_conn_test.h \
	ngtcp2_ringbuf_test.h \
	ngtcp2_conv_test.h \
	ngtcp2_ksl_test.h \
	ngtcp2_gaptr_test.h \
	ngtcp2_vec_test.h \
	ngtcp2_strm_test.h \
	ngtcp2_pv_test.h \
	ngtcp2_pmtud_test.h \
	ngtcp2_str_test.h \
	ngtcp2_tstamp_test.h \
	ngtcp2_conversion_test.h \
	ngtcp2_cc_test.h \
	ngtcp2_test_helper.h

main_SOURCES = $(HFILES) $(OBJECTS)

# With static lib disabled and symbol hiding enabled, we have to link object
# files directly because the tests use symbols not included in public API.
if ENABLE_SHARED
main_LDADD = ${top_builddir}/lib/.libs/*.o
else
main_LDADD = ${top_builddir}/lib/.libs/libngtcp2.la
endif
main_LDADD += @CUNIT_LIBS@
main_LDFLAGS = -static

AM_CFLAGS = $(WARNCFLAGS) \
	-I${top_srcdir}/lib \
	-I${top_srcdir}/lib/includes \
	-I${top_builddir}/lib/includes \
	-DBUILDING_NGTCP2 \
	@CUNIT_CFLAGS@ @DEFS@
AM_LDFLAGS = -no-install

TESTS = main

endif # HAVE_CUNIT
