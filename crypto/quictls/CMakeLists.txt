# ngtcp2

# Copyright (c) 2019 ngtcp2

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

add_definitions(-DBUILDING_NGTCP2)

set(ngtcp2_crypto_quictls_SOURCES
  quictls.c
  ../shared.c
)

set(ngtcp2_crypto_quictls_INCLUDE_DIRS
  "${CMAKE_CURRENT_SOURCE_DIR}/../../lib/includes"
  "${CMAKE_CURRENT_BINARY_DIR}/../../lib/includes"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../lib"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../crypto/includes"
  "${CMAKE_CURRENT_BINARY_DIR}/../../crypto/includes"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../crypto"
  "${CMAKE_CURRENT_BINARY_DIR}/../../crypto"
  "${OPENSSL_INCLUDE_DIRS}"
)

foreach(name libngtcp2_crypto_quictls.pc)
  configure_file("${name}.in" "${name}" @ONLY)
endforeach()

# Public shared library
if(ENABLE_SHARED_LIB)
  add_library(ngtcp2_crypto_quictls SHARED ${ngtcp2_crypto_quictls_SOURCES})
  set_target_properties(ngtcp2_crypto_quictls PROPERTIES
    COMPILE_FLAGS "${WARNCFLAGS}"
    VERSION ${CRYPTO_QUICTLS_LT_VERSION}
    SOVERSION ${CRYPTO_QUICTLS_LT_SOVERSION}
    C_VISIBILITY_PRESET hidden
    POSITION_INDEPENDENT_CODE ON
  )
  target_include_directories(ngtcp2_crypto_quictls PUBLIC
    ${ngtcp2_crypto_quictls_INCLUDE_DIRS})
  target_link_libraries(ngtcp2_crypto_quictls ngtcp2 ${OPENSSL_LIBRARIES})

  install(TARGETS ngtcp2_crypto_quictls
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
endif()

if(ENABLE_STATIC_LIB)
  # Public static library
  add_library(ngtcp2_crypto_quictls_static STATIC ${ngtcp2_crypto_quictls_SOURCES})
  set_target_properties(ngtcp2_crypto_quictls_static PROPERTIES
    COMPILE_FLAGS "${WARNCFLAGS}"
    VERSION ${CRYPTO_QUICTLS_LT_VERSION}
    SOVERSION ${CRYPTO_QUICTLS_LT_SOVERSION}
    ARCHIVE_OUTPUT_NAME ngtcp2_crypto_quictls${STATIC_LIB_SUFFIX}
    C_VISIBILITY_PRESET hidden
  )
  target_compile_definitions(ngtcp2_crypto_quictls_static PUBLIC
    "-DNGTCP2_STATICLIB")
  target_include_directories(ngtcp2_crypto_quictls_static PUBLIC
    ${ngtcp2_crypto_quictls_INCLUDE_DIRS})

  install(TARGETS ngtcp2_crypto_quictls_static
    DESTINATION "${CMAKE_INSTALL_LIBDIR}")
endif()

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/libngtcp2_crypto_quictls.pc"
  DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")
