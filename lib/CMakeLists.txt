
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
  ngtcp2_frame_chain.c
  ngtcp2_strm.c
  ngtcp2_idtr.c
  ngtcp2_gaptr.c
  ngtcp2_ringbuf.c
  ngtcp2_log.c
  ngtcp2_qlog.c
  ngtcp2_cid.c
  ngtcp2_ksl.c
  ngtcp2_cc.c
  ngtcp2_bbr.c
  ngtcp2_addr.c
  ngtcp2_path.c
  ngtcp2_pv.c
  ngtcp2_pmtud.c
  ngtcp2_version.c
  ngtcp2_rst.c
  ngtcp2_window_filter.c
  ngtcp2_opl.c
  ngtcp2_balloc.c
  ngtcp2_objalloc.c
  ngtcp2_unreachable.c
  ngtcp2_conversion.c
)

set(ngtcp2_INCLUDE_DIRS
  "${CMAKE_CURRENT_SOURCE_DIR}/includes"
  "${CMAKE_CURRENT_BINARY_DIR}/includes"
)

# Public shared library
if(ENABLE_SHARED_LIB)
  add_library(ngtcp2 SHARED ${ngtcp2_SOURCES})
  set_target_properties(ngtcp2 PROPERTIES
    COMPILE_FLAGS "${WARNCFLAGS}"
    VERSION ${LT_VERSION} SOVERSION ${LT_SOVERSION}
    C_VISIBILITY_PRESET hidden
    POSITION_INDEPENDENT_CODE ON
  )
  target_include_directories(ngtcp2 PUBLIC ${ngtcp2_INCLUDE_DIRS})

  install(TARGETS ngtcp2
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
endif()

if(HAVE_CUNIT OR ENABLE_STATIC_LIB)
  # Static library (for unittests because of symbol visibility)
  add_library(ngtcp2_static STATIC ${ngtcp2_SOURCES})
  set_target_properties(ngtcp2_static PROPERTIES
    COMPILE_FLAGS "${WARNCFLAGS}"
    VERSION ${LT_VERSION} SOVERSION ${LT_SOVERSION}
    ARCHIVE_OUTPUT_NAME ngtcp2${STATIC_LIB_SUFFIX}
    C_VISIBILITY_PRESET hidden
  )
  target_compile_definitions(ngtcp2_static PUBLIC "-DNGTCP2_STATICLIB")
  target_include_directories(ngtcp2_static PUBLIC ${ngtcp2_INCLUDE_DIRS})
  if(ENABLE_STATIC_LIB)
    install(TARGETS ngtcp2_static
      DESTINATION "${CMAKE_INSTALL_LIBDIR}")
  endif()
endif()

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/libngtcp2.pc"
  DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")
