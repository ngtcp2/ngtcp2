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

if(LIBEV_FOUND AND OPENSSL_FOUND AND LIBNGHTTP3_FOUND)
  include_directories(
    ${CMAKE_SOURCE_DIR}/lib/includes
    ${CMAKE_BINARY_DIR}/lib/includes
    ${CMAKE_SOURCE_DIR}/third-party
    ${CMAKE_SOURCE_DIR}/crypto/includes

    ${OPENSSL_INCLUDE_DIRS}
    ${LIBEV_INCLUDE_DIRS}
    ${LIBNGHTTP3_INCLUDE_DIRS}
  )

  link_libraries(
    ngtcp2_crypto_openssl
    ngtcp2
    ${OPENSSL_LIBRARIES}
    ${LIBEV_LIBRARIES}
    ${LIBNGHTTP3_LIBRARIES}
  )

  set(client_SOURCES
    client.cc
    debug.cc
    util.cc
    keylog.cc
    shared.cc
  )

  set(server_SOURCES
    server.cc
    debug.cc
    util.cc
    keylog.cc
    http.cc
    shared.cc
  )

  add_executable(client ${client_SOURCES} $<TARGET_OBJECTS:http-parser>)
  add_executable(server ${server_SOURCES} $<TARGET_OBJECTS:http-parser>)
  set_target_properties(client PROPERTIES
    COMPILE_FLAGS "${WARNCXXFLAGS}"
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
  )
  set_target_properties(server PROPERTIES
    COMPILE_FLAGS "${WARNCXXFLAGS}"
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
  )

  # TODO prevent client and example servers from being installed?
else()
  message(WARNING "Examples are disabled due to lack of good libev, OpenSSL or libnghttp3")
endif()
