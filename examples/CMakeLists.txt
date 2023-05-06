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

if(LIBEV_FOUND AND HAVE_OPENSSL)
  set(client_SOURCES
    client.cc
    client_base.cc
    debug.cc
    util.cc
    shared.cc
    tls_client_context_openssl.cc
    tls_client_session_openssl.cc
    tls_session_base_openssl.cc
    util_openssl.cc
  )

 
  set(ossl_INCLUDE_DIRS
    ${CMAKE_SOURCE_DIR}/lib/includes
    ${CMAKE_BINARY_DIR}/lib/includes
    ${CMAKE_SOURCE_DIR}/third-party
    ${CMAKE_SOURCE_DIR}/crypto/includes

    ${JEMALLOC_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIRS}
    ${LIBEV_INCLUDE_DIRS}
    ${LIBNGHTTP3_INCLUDE_DIRS}
  )

  set(ossl_LIBS
    ngtcp2_crypto_openssl
    ngtcp2
    ${JEMALLOC_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ${LIBEV_LIBRARIES}
    ${LIBNGHTTP3_LIBRARIES}
  )

  add_executable(client ${client_SOURCES} $<TARGET_OBJECTS:http-parser>)

  set_target_properties(client PROPERTIES
    COMPILE_FLAGS "${WARNCXXFLAGS} -DENABLE_EXAMPLE_OPENSSL -DWITH_EXAMPLE_OPENSSL"
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
  )

  target_include_directories(client PUBLIC ${ossl_INCLUDE_DIRS})
  target_link_libraries(client ${ossl_LIBS})

endif()

if(LIBEV_FOUND AND HAVE_BORINGSSL)
  set(bsslclient_SOURCES
    client.cc
    client_base.cc
    debug.cc
    util.cc
    shared.cc
    tls_client_context_boringssl.cc
    tls_client_session_boringssl.cc
    tls_session_base_openssl.cc
    util_openssl.cc
  )


  set(bssl_INCLUDE_DIRS
    ${CMAKE_SOURCE_DIR}/lib/includes
    ${CMAKE_BINARY_DIR}/lib/includes
    ${CMAKE_SOURCE_DIR}/third-party
    ${CMAKE_SOURCE_DIR}/crypto/includes

    ${JEMALLOC_INCLUDE_DIRS}
    ${BORINGSSL_INCLUDE_DIRS}
    ${LIBEV_INCLUDE_DIRS}
    ${LIBNGHTTP3_INCLUDE_DIRS}
  )

  set(bssl_LIBS
    ngtcp2_crypto_boringssl_static
    ngtcp2
    ${JEMALLOC_LIBRARIES}
    ${BORINGSSL_LIBRARIES}
    ${LIBEV_LIBRARIES}
    ${LIBNGHTTP3_LIBRARIES}
  )

  add_executable(bsslclient ${bsslclient_SOURCES} $<TARGET_OBJECTS:http-parser>)
  set_target_properties(bsslclient PROPERTIES
    COMPILE_FLAGS "${WARNCXXFLAGS} -DENABLE_EXAMPLE_BORINGSSL -DWITH_EXAMPLE_BORINGSSL"
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
  )

  target_include_directories(bsslclient PUBLIC ${bssl_INCLUDE_DIRS})
  target_link_libraries(bsslclient ${bssl_LIBS})

endif()

