# ngtcp2

# Copyright (c) 2022 ngtcp2

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

add_compile_definitions(-DBUILDING_NGTCP2)

set(ngtcp2_crypto_wolfssl_SOURCES
  wolfssl.c
  ../shared.c
)

set(ngtcp2_crypto_wolfssl_INCLUDE_DIRS
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../includes>
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/..>
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../../lib>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

foreach(name libngtcp2_crypto_wolfssl.pc)
  configure_file("${name}.in" "${name}" @ONLY)
endforeach()

# Public shared library
if(ENABLE_SHARED_LIB)
  add_library(ngtcp2_crypto_wolfssl SHARED ${ngtcp2_crypto_wolfssl_SOURCES})
  set_target_properties(ngtcp2_crypto_wolfssl PROPERTIES
    COMPILE_FLAGS "${WARNCFLAGS}"
    VERSION ${CRYPTO_WOLFSSL_LT_VERSION}
    SOVERSION ${CRYPTO_WOLFSSL_LT_SOVERSION}
    C_VISIBILITY_PRESET hidden
    POSITION_INDEPENDENT_CODE ON
  )
  target_include_directories(ngtcp2_crypto_wolfssl PUBLIC
    ${ngtcp2_crypto_wolfssl_INCLUDE_DIRS})
  target_link_libraries(ngtcp2_crypto_wolfssl PUBLIC ngtcp2 ${WOLFSSL_LINK_TARGET})

  install(TARGETS ngtcp2_crypto_wolfssl
    EXPORT ${NGTCP2_TARGETS_EXPORT_NAME}
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
endif()

if(ENABLE_STATIC_LIB)
  # Public static library
  add_library(ngtcp2_crypto_wolfssl_static STATIC ${ngtcp2_crypto_wolfssl_SOURCES})
  set_target_properties(ngtcp2_crypto_wolfssl_static PROPERTIES
    COMPILE_FLAGS "${WARNCFLAGS}"
    ARCHIVE_OUTPUT_NAME ngtcp2_crypto_wolfssl${STATIC_LIB_SUFFIX}
    C_VISIBILITY_PRESET hidden
  )
  target_include_directories(ngtcp2_crypto_wolfssl_static PUBLIC
    ${ngtcp2_crypto_wolfssl_INCLUDE_DIRS})
  # There is no linking for static lib, but it brings required include paths
  # and compile definitions from dependencies
  target_link_libraries(ngtcp2_crypto_wolfssl_static PUBLIC ngtcp2_static ${WOLFSSL_LINK_TARGET})

  install(TARGETS ngtcp2_crypto_wolfssl_static
    EXPORT ${NGTCP2_TARGETS_EXPORT_NAME}
    DESTINATION "${CMAKE_INSTALL_LIBDIR}")
endif()

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/libngtcp2_crypto_wolfssl.pc"
  DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")
