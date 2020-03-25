# ngtcp2

# Copyright (c) 2020 ngtcp2

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

set(ngtcp2_crypto_gnutls_SOURCES
  gnutls.c
  ../shared.c
)

set(ngtcp2_crypto_gnutls_INCLUDE_DIRS
  "${CMAKE_CURRENT_SOURCE_DIR}/../../lib/includes"
  "${CMAKE_CURRENT_BINARY_DIR}/../../lib/includes"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../lib"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../crypto/includes"
  "${CMAKE_CURRENT_BINARY_DIR}/../../crypto/includes"
  "${GNUTLS_INCLUDE_DIRS}"
)

foreach(name libngtcp2_crypto_gnutls.pc)
  configure_file("${name}.in" "${name}" @ONLY)
endforeach()

# Public shared library
add_library(ngtcp2_crypto_gnutls ${ngtcp2_crypto_gnutls_SOURCES})
set_target_properties(ngtcp2_crypto_gnutls PROPERTIES
  COMPILE_FLAGS "${WARNCFLAGS}"
  VERSION ${LT_VERSION} SOVERSION ${LT_SOVERSION}
  C_VISIBILITY_PRESET hidden
)

target_include_directories(ngtcp2_crypto_gnutls PUBLIC
  ${ngtcp2_crypto_gnutls_INCLUDE_DIRS})
if(NOT BUILD_SHARED_LIBS)
  target_compile_definitions(ngtcp2_crypto_gnutls PUBLIC "-DNGTCP2_STATICLIB")
endif()

install(TARGETS ngtcp2_crypto_gnutls
  DESTINATION "${CMAKE_INSTALL_LIBDIR}")

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/libngtcp2_crypto_gnutls.pc"
  DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")
