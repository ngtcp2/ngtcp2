
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
  ngtcp2_transport_params.c
  ngtcp2_settings.c
)

set(ngtcp2_INCLUDE_DIRS
  "${CMAKE_CURRENT_SOURCE_DIR}/includes"
  "${CMAKE_CURRENT_BINARY_DIR}/includes"
)

set(NGTCP2_GENERATED_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated")
set(NGTCP2_VERSION_CONFIG "${NGTCP2_GENERATED_DIR}/${PROJECT_NAME}ConfigVersion.cmake")
set(NGTCP2_PROJECT_CONFIG "${NGTCP2_GENERATED_DIR}/${PROJECT_NAME}Config.cmake")
set(NGTCP2_TARGETS_EXPORT_NAME "${PROJECT_NAME}Targets")
set(NGTCP2_CONFIG_INSTALL_DIR "lib/cmake/${PROJECT_NAME}")
set(NGTCP2_NAMESPACE "${PROJECT_NAME}::")
set(NGTCP2_VERSION ${PROJECT_VERSION})

include(CMakePackageConfigHelpers)
write_basic_package_version_file(
  "${NGTCP2_VERSION_CONFIG}" VERSION ${NGTCP2_VERSION} COMPATIBILITY SameMajorVersion
)
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/config.cmake.in" "${NGTCP2_PROJECT_CONFIG}" @ONLY)

# Install cmake config files
install(
  FILES "${NGTCP2_PROJECT_CONFIG}" "${NGTCP2_VERSION_CONFIG}"
  DESTINATION "${NGTCP2_CONFIG_INSTALL_DIR}")

# Public shared library
if(ENABLE_SHARED_LIB)
  add_library(ngtcp2 SHARED ${ngtcp2_SOURCES})
  set_target_properties(ngtcp2 PROPERTIES
    COMPILE_FLAGS "${WARNCFLAGS}"
    VERSION ${LT_VERSION} SOVERSION ${LT_SOVERSION}
    C_VISIBILITY_PRESET hidden
    POSITION_INDEPENDENT_CODE ON
  )
  foreach(include_DIR IN LISTS ngtcp2_INCLUDE_DIRS)
    target_include_directories(ngtcp2 PUBLIC $<BUILD_INTERFACE:${include_DIR}>)
  endforeach()

  target_include_directories(ngtcp2 PUBLIC $<INSTALL_INTERFACE:./include>)

  install(TARGETS ngtcp2
    EXPORT ${NGTCP2_TARGETS_EXPORT_NAME}
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
endif()

if(ENABLE_STATIC_LIB)
  # Public static library
  add_library(ngtcp2_static STATIC ${ngtcp2_SOURCES})
  set_target_properties(ngtcp2_static PROPERTIES
    COMPILE_FLAGS "${WARNCFLAGS}"
    VERSION ${LT_VERSION} SOVERSION ${LT_SOVERSION}
    ARCHIVE_OUTPUT_NAME ngtcp2${STATIC_LIB_SUFFIX}
    C_VISIBILITY_PRESET hidden
  )
  target_compile_definitions(ngtcp2_static PUBLIC "-DNGTCP2_STATICLIB")
  foreach(include_DIR IN LISTS ngtcp2_INCLUDE_DIRS)
    target_include_directories(ngtcp2_static PUBLIC $<BUILD_INTERFACE:${include_DIR}>)
  endforeach()

  target_include_directories(ngtcp2_static PUBLIC $<INSTALL_INTERFACE:./include>)

  install(TARGETS ngtcp2_static
    EXPORT ${NGTCP2_TARGETS_EXPORT_NAME}
    DESTINATION "${CMAKE_INSTALL_LIBDIR}")
endif()

install(
  EXPORT "${NGTCP2_TARGETS_EXPORT_NAME}"
  NAMESPACE "${NGTCP2_NAMESPACE}"
  DESTINATION "${NGTCP2_CONFIG_INSTALL_DIR}")

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/libngtcp2.pc"
  DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")
