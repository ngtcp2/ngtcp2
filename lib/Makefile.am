# ngtcp2

# Copyright (c) 2016 - 2019 ngtcp2 contributors

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
SUBDIRS = includes

EXTRA_DIST = CMakeLists.txt

AM_CFLAGS = $(WARNCFLAGS) $(DEBUGCFLAGS) $(EXTRACFLAG)
AM_CPPFLAGS = -I$(srcdir)/includes -I$(builddir)/includes -DBUILDING_NGTCP2
AM_LDFLAGS = ${LIBTOOL_LDFLAGS}

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libngtcp2.pc
DISTCLEANFILES = $(pkgconfig_DATA)

lib_LTLIBRARIES = libngtcp2.la

OBJECTS = \
	ngtcp2_pkt.c \
	ngtcp2_conv.c \
	ngtcp2_str.c \
	ngtcp2_vec.c \
	ngtcp2_buf.c \
	ngtcp2_conn.c \
	ngtcp2_mem.c \
	ngtcp2_pq.c \
	ngtcp2_map.c \
	ngtcp2_rob.c \
	ngtcp2_ppe.c \
	ngtcp2_crypto.c \
	ngtcp2_err.c \
	ngtcp2_range.c \
	ngtcp2_acktr.c \
	ngtcp2_rtb.c \
	ngtcp2_strm.c \
	ngtcp2_idtr.c \
	ngtcp2_gaptr.c \
	ngtcp2_ringbuf.c \
	ngtcp2_log.c \
	ngtcp2_qlog.c \
	ngtcp2_cid.c \
	ngtcp2_ksl.c \
	ngtcp2_cc.c \
	ngtcp2_bbr.c \
	ngtcp2_bbr2.c \
	ngtcp2_addr.c \
	ngtcp2_path.c \
	ngtcp2_pv.c \
	ngtcp2_pmtud.c \
	ngtcp2_version.c \
	ngtcp2_rst.c \
	ngtcp2_window_filter.c \
	ngtcp2_opl.c \
	ngtcp2_balloc.c \
	ngtcp2_objalloc.c \
	ngtcp2_unreachable.c \
	ngtcp2_conversion.c

HFILES = \
	ngtcp2_pkt.h \
	ngtcp2_conv.h \
	ngtcp2_str.h \
	ngtcp2_vec.h \
	ngtcp2_buf.h \
	ngtcp2_conn.h \
	ngtcp2_mem.h \
	ngtcp2_pq.h \
	ngtcp2_map.h \
	ngtcp2_rob.h \
	ngtcp2_ppe.h \
	ngtcp2_crypto.h \
	ngtcp2_err.h \
	ngtcp2_range.h \
	ngtcp2_acktr.h \
	ngtcp2_rtb.h \
	ngtcp2_strm.h \
	ngtcp2_idtr.h \
	ngtcp2_gaptr.h \
	ngtcp2_ringbuf.h \
	ngtcp2_log.h \
	ngtcp2_qlog.h \
	ngtcp2_cid.h \
	ngtcp2_ksl.h \
	ngtcp2_cc.h \
	ngtcp2_bbr.h \
	ngtcp2_bbr2.h \
	ngtcp2_addr.h \
	ngtcp2_path.h \
	ngtcp2_pv.h \
	ngtcp2_pmtud.h \
	ngtcp2_macro.h \
	ngtcp2_rst.h \
	ngtcp2_window_filter.h \
	ngtcp2_opl.h \
	ngtcp2_balloc.h \
	ngtcp2_objalloc.h \
	ngtcp2_rcvry.h \
	ngtcp2_net.h \
	ngtcp2_unreachable.h \
	ngtcp2_conversion.h \
	ngtcp2_conn_stat.h \
	ngtcp2_pktns_id.h \
	ngtcp2_tstamp.h

libngtcp2_la_SOURCES = $(HFILES) $(OBJECTS)
libngtcp2_la_LDFLAGS = -no-undefined \
	-version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE)
