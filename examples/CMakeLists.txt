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

if(LIBEV_FOUND AND HAVE_OPENSSL AND LIBNGHTTP3_FOUND)
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

  set(server_SOURCES
    server.cc
    server_base.cc
    debug.cc
    util.cc
    http.cc
    shared.cc
    tls_server_context_openssl.cc
    tls_server_session_openssl.cc
    tls_session_base_openssl.cc
    util_openssl.cc util_aead_openssl.cc
  )

  set(ossl_INCLUDE_DIRS
    ${CMAKE_SOURCE_DIR}/lib/includes
    ${CMAKE_BINARY_DIR}/lib/includes
    ${CMAKE_SOURCE_DIR}/third-party
    ${CMAKE_SOURCE_DIR}/crypto/includes

    ${OPENSSL_INCLUDE_DIRS}
    ${LIBEV_INCLUDE_DIRS}
    ${LIBNGHTTP3_INCLUDE_DIRS}
  )

  set(ossl_LIBS
    ngtcp2_crypto_openssl
    ngtcp2
    ${OPENSSL_LIBRARIES}
    ${LIBEV_LIBRARIES}
    ${LIBNGHTTP3_LIBRARIES}
  )

  add_executable(client ${client_SOURCES} $<TARGET_OBJECTS:http-parser>)
  add_executable(server ${server_SOURCES} $<TARGET_OBJECTS:http-parser>)
  set_target_properties(client PROPERTIES
    COMPILE_FLAGS "${WARNCXXFLAGS} -DENABLE_EXAMPLE_OPENSSL -DWITH_EXAMPLE_OPENSSL"
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
  )
  set_target_properties(server PROPERTIES
    COMPILE_FLAGS "${WARNCXXFLAGS} -DENABLE_EXAMPLE_OPENSSL -DWITH_EXAMPLE_OPENSSL"
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
  )
  target_include_directories(client PUBLIC ${ossl_INCLUDE_DIRS})
  target_include_directories(server PUBLIC ${ossl_INCLUDE_DIRS})
  target_link_libraries(client ${ossl_LIBS})
  target_link_libraries(server ${ossl_LIBS})

  # TODO prevent client and example servers from being installed?
endif()

if(LIBEV_FOUND AND HAVE_GNUTLS AND LIBNGHTTP3_FOUND)
  set(gtlsclient_SOURCES
    client.cc
    client_base.cc
    debug.cc
    util.cc
    shared.cc
    tls_client_context_gnutls.cc
    tls_client_session_gnutls.cc
    tls_session_base_gnutls.cc
    util_gnutls.cc
  )

  set(gtlsserver_SOURCES
    server.cc
    server_base.cc
    debug.cc
    util.cc
    http.cc
    shared.cc
    tls_server_context_gnutls.cc
    tls_server_session_gnutls.cc
    tls_session_base_gnutls.cc
    util_gnutls.cc
  )

  set(gtls_INCLUDE_DIRS
    ${CMAKE_SOURCE_DIR}/lib/includes
    ${CMAKE_BINARY_DIR}/lib/includes
    ${CMAKE_SOURCE_DIR}/third-party
    ${CMAKE_SOURCE_DIR}/crypto/includes

    ${GNUTLS_INCLUDE_DIRS}
    ${LIBEV_INCLUDE_DIRS}
    ${LIBNGHTTP3_INCLUDE_DIRS}
  )

  set(gtls_LIBS
    ngtcp2_crypto_gnutls
    ngtcp2
    ${GNUTLS_LIBRARIES}
    ${LIBEV_LIBRARIES}
    ${LIBNGHTTP3_LIBRARIES}
  )

  add_executable(gtlsclient ${gtlsclient_SOURCES} $<TARGET_OBJECTS:http-parser>)
  add_executable(gtlsserver ${gtlsserver_SOURCES} $<TARGET_OBJECTS:http-parser>)
  set_target_properties(gtlsclient PROPERTIES
    COMPILE_FLAGS "${WARNCXXFLAGS} -DENABLE_EXAMPLE_GNUTLS -DWITH_EXAMPLE_GNUTLS"
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
  )
  set_target_properties(gtlsserver PROPERTIES
    COMPILE_FLAGS "${WARNCXXFLAGS} -DENABLE_EXAMPLE_GNUTLS -DWITH_EXAMPLE_GNUTLS"
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
  )
  target_include_directories(gtlsclient PUBLIC ${gtls_INCLUDE_DIRS})
  target_include_directories(gtlsserver PUBLIC ${gtls_INCLUDE_DIRS})
  target_link_libraries(gtlsclient ${gtls_LIBS})
  target_link_libraries(gtlsserver ${gtls_LIBS})

  # TODO prevent gtlsclient and example gtlsservers from being installed?
endif()

if(LIBEV_FOUND AND HAVE_BORINGSSL AND LIBNGHTTP3_FOUND)
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

  set(bsslserver_SOURCES
    server.cc
    server_base.cc
    debug.cc
    util.cc
    http.cc
    shared.cc
    tls_server_context_boringssl.cc
    tls_server_session_boringssl.cc
    tls_session_base_openssl.cc
    util_openssl.cc util_aead_boringssl.cc
  )

  set(bssl_INCLUDE_DIRS
    ${CMAKE_SOURCE_DIR}/lib/includes
    ${CMAKE_BINARY_DIR}/lib/includes
    ${CMAKE_SOURCE_DIR}/third-party
    ${CMAKE_SOURCE_DIR}/crypto/includes

    ${BORINGSSL_INCLUDE_DIRS}
    ${LIBEV_INCLUDE_DIRS}
    ${LIBNGHTTP3_INCLUDE_DIRS}
  )

  set(bssl_LIBS
    ngtcp2_crypto_boringssl
    ngtcp2
    ${BORINGSSL_LIBRARIES}
    ${LIBEV_LIBRARIES}
    ${LIBNGHTTP3_LIBRARIES}
  )

  add_executable(bsslclient ${bsslclient_SOURCES} $<TARGET_OBJECTS:http-parser>)
  add_executable(bsslserver ${bsslserver_SOURCES} $<TARGET_OBJECTS:http-parser>)
  set_target_properties(bsslclient PROPERTIES
    COMPILE_FLAGS "${WARNCXXFLAGS} -DENABLE_EXAMPLE_BORINGSSL -DWITH_EXAMPLE_BORINGSSL"
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
  )
  set_target_properties(bsslserver PROPERTIES
    COMPILE_FLAGS "${WARNCXXFLAGS} -DENABLE_EXAMPLE_BORINGSSL -DWITH_EXAMPLE_BORINGSSL"
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
  )
  target_include_directories(bsslclient PUBLIC ${bssl_INCLUDE_DIRS})
  target_include_directories(bsslserver PUBLIC ${bssl_INCLUDE_DIRS})
  target_link_libraries(bsslclient ${bssl_LIBS})
  target_link_libraries(bsslserver ${bssl_LIBS})

  # TODO prevent bsslclient and example bsslservers from being installed?
endif()
