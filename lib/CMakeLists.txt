
# ngtcp2

# Copyright (c) 2016 ngtcp2

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

add_subdirectory(includes)

add_definitions(-DBUILDING_NGTCP2)

set(ngtcp2_SOURCES
  ngtcp2_pkt.c
  ngtcp2_conv.c
  ngtcp2_str.c
  ngtcp2_vec.c
  ngtcp2_buf.c
  ngtcp2_conn.c
  ngtcp2_mem.c
  ngtcp2_pq.c
  ngtcp2_map.c
  ngtcp2_rob.c
  ngtcp2_ppe.c
  ngtcp2_crypto.c
  ngtcp2_err.c
  ngtcp2_range.c
  ngtcp2_acktr.c
  ngtcp2_rtb.c
  ngtcp2_strm.c
  ngtcp2_idtr.c
  ngtcp2_gaptr.c
  ngtcp2_ringbuf.c
  ngtcp2_log.c
  ngtcp2_qlog.c
  ngtcp2_cid.c
  ngtcp2_ksl.c
  ngtcp2_cc.c
  ngtcp2_addr.c
  ngtcp2_path.c
  ngtcp2_pv.c
  ngtcp2_version.c
)

set(ngtcp2_INCLUDE_DIRS
  "${CMAKE_CURRENT_SOURCE_DIR}/includes"
  "${CMAKE_CURRENT_BINARY_DIR}/includes"
)

# Public shared library
add_library(ngtcp2 ${ngtcp2_SOURCES})
set_target_properties(ngtcp2 PROPERTIES
  COMPILE_FLAGS "${WARNCFLAGS}"
  VERSION ${LT_VERSION} SOVERSION ${LT_SOVERSION}
  C_VISIBILITY_PRESET hidden
)

target_include_directories(ngtcp2 PUBLIC ${ngtcp2_INCLUDE_DIRS})
if(NOT BUILD_SHARED_LIBS)
  target_compile_definitions(ngtcp2 PUBLIC "-DNGTCP2_STATICLIB")
endif()

if(HAVE_CUNIT)
  # Static library (for unittests because of symbol visibility)
  add_library(ngtcp2_static STATIC ${ngtcp2_SOURCES})
  set_target_properties(ngtcp2_static PROPERTIES
    COMPILE_FLAGS "${WARNCFLAGS}"
    VERSION ${LT_VERSION} SOVERSION ${LT_SOVERSION}
  )
  target_include_directories(ngtcp2_static PUBLIC ${ngtcp2_INCLUDE_DIRS})
  target_compile_definitions(ngtcp2_static PUBLIC "-DNGTCP2_STATICLIB")
endif()

install(TARGETS ngtcp2
  DESTINATION "${CMAKE_INSTALL_LIBDIR}")

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/libngtcp2.pc"
  DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")
