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
  set(qtlsclient_SOURCES
    client.cc
    client_base.cc
    debug.cc
    util.cc
    shared.cc
    tls_client_context_quictls.cc
    tls_client_session_quictls.cc
    tls_session_base_quictls.cc
    util_openssl.cc
  )

  set(qtlsserver_SOURCES
    server.cc
    server_base.cc
    debug.cc
    util.cc
    http.cc
    shared.cc
    tls_server_context_quictls.cc
    tls_server_session_quictls.cc
    tls_session_base_quictls.cc
    util_openssl.cc
  )

  set(qtls_INCLUDE_DIRS
    ${CMAKE_SOURCE_DIR}/lib/includes
    ${CMAKE_BINARY_DIR}/lib/includes
    ${CMAKE_SOURCE_DIR}/third-party
    ${CMAKE_SOURCE_DIR}/third-party/urlparse
    ${CMAKE_SOURCE_DIR}/crypto/includes

    ${JEMALLOC_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIRS}
    ${LIBEV_INCLUDE_DIRS}
    ${LIBNGHTTP3_INCLUDE_DIRS}
  )

  set(qtls_LIBS
    ngtcp2_crypto_quictls
    ngtcp2
    ${JEMALLOC_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ${LIBEV_LIBRARIES}
    ${LIBNGHTTP3_LIBRARIES}
  )

  add_executable(qtlsclient ${qtlsclient_SOURCES}
    $<TARGET_OBJECTS:urlparse>
  )
  add_executable(qtlsserver ${qtlsserver_SOURCES}
    $<TARGET_OBJECTS:urlparse>
  )
  set_target_properties(qtlsclient PROPERTIES
    COMPILE_FLAGS "${WARNCXXFLAGS} -DENABLE_EXAMPLE_QUICTLS -DWITH_EXAMPLE_QUICTLS"
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
  )
  set_target_properties(qtlsserver PROPERTIES
    COMPILE_FLAGS "${WARNCXXFLAGS} -DENABLE_EXAMPLE_QUICTLS -DWITH_EXAMPLE_QUICTLS"
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
  )
  target_include_directories(qtlsclient PUBLIC ${qtls_INCLUDE_DIRS})
  target_include_directories(qtlsserver PUBLIC ${qtls_INCLUDE_DIRS})
  target_link_libraries(qtlsclient ${qtls_LIBS})
  target_link_libraries(qtlsserver ${qtls_LIBS})

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
    ${CMAKE_SOURCE_DIR}/third-party/urlparse
    ${CMAKE_SOURCE_DIR}/crypto/includes

    ${JEMALLOC_INCLUDE_DIRS}
    ${GNUTLS_INCLUDE_DIRS}
    ${LIBEV_INCLUDE_DIRS}
    ${LIBNGHTTP3_INCLUDE_DIRS}
  )

  set(gtls_LIBS
    ngtcp2_crypto_gnutls
    ngtcp2
    ${JEMALLOC_LIBRARIES}
    ${GNUTLS_LIBRARIES}
    ${LIBEV_LIBRARIES}
    ${LIBNGHTTP3_LIBRARIES}
  )

  add_executable(gtlsclient ${gtlsclient_SOURCES}
    $<TARGET_OBJECTS:urlparse>
  )
  add_executable(gtlsserver ${gtlsserver_SOURCES}
    $<TARGET_OBJECTS:urlparse>
  )
  set_target_properties(gtlsclient PROPERTIES
    COMPILE_FLAGS "${WARNCXXFLAGS} -DENABLE_EXAMPLE_GNUTLS -DWITH_EXAMPLE_GNUTLS"
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
  )
  set_target_properties(gtlsserver PROPERTIES
    COMPILE_FLAGS "${WARNCXXFLAGS} -DENABLE_EXAMPLE_GNUTLS -DWITH_EXAMPLE_GNUTLS"
    CXX_STANDARD 20
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
    tls_session_base_quictls.cc
    tls_shared_boringssl.cc
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
    tls_session_base_quictls.cc
    tls_shared_boringssl.cc
    util_openssl.cc
  )

  set(bssl_INCLUDE_DIRS
    ${CMAKE_SOURCE_DIR}/lib/includes
    ${CMAKE_BINARY_DIR}/lib/includes
    ${CMAKE_SOURCE_DIR}/third-party
    ${CMAKE_SOURCE_DIR}/third-party/urlparse
    ${CMAKE_SOURCE_DIR}/crypto/includes

    ${JEMALLOC_INCLUDE_DIRS}
    ${BORINGSSL_INCLUDE_DIRS}
    ${LIBEV_INCLUDE_DIRS}
    ${LIBNGHTTP3_INCLUDE_DIRS}
    ${LIBBROTLIENC_INCLUDE_DIRS}
    ${LIBBROTLIDEC_INCLUDE_DIRS}
  )

  set(bssl_LIBS
    ngtcp2_crypto_boringssl_static
    ngtcp2
    ${JEMALLOC_LIBRARIES}
    ${BORINGSSL_LIBRARIES}
    ${LIBEV_LIBRARIES}
    ${LIBNGHTTP3_LIBRARIES}
    ${LIBBROTLIENC_LIBRARIES}
    ${LIBBROTLIDEC_LIBRARIES}
  )

  add_executable(bsslclient ${bsslclient_SOURCES}
    $<TARGET_OBJECTS:urlparse>
  )
  add_executable(bsslserver ${bsslserver_SOURCES}
    $<TARGET_OBJECTS:urlparse>
  )
  set_target_properties(bsslclient PROPERTIES
    COMPILE_FLAGS "${WARNCXXFLAGS} -DENABLE_EXAMPLE_BORINGSSL -DWITH_EXAMPLE_BORINGSSL"
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
  )
  set_target_properties(bsslserver PROPERTIES
    COMPILE_FLAGS "${WARNCXXFLAGS} -DENABLE_EXAMPLE_BORINGSSL -DWITH_EXAMPLE_BORINGSSL"
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
  )
  target_include_directories(bsslclient PUBLIC ${bssl_INCLUDE_DIRS})
  target_include_directories(bsslserver PUBLIC ${bssl_INCLUDE_DIRS})
  target_link_libraries(bsslclient ${bssl_LIBS})
  target_link_libraries(bsslserver ${bssl_LIBS})

  # TODO prevent bsslclient and example bsslservers from being installed?
endif()

if(LIBEV_FOUND AND HAVE_PICOTLS AND LIBNGHTTP3_FOUND)
  set(ptlsclient_SOURCES
    client.cc
    client_base.cc
    debug.cc
    util.cc
    shared.cc
    tls_client_context_picotls.cc
    tls_client_session_picotls.cc
    tls_session_base_picotls.cc
    tls_shared_picotls.cc
    util_openssl.cc
  )

  set(ptlsserver_SOURCES
    server.cc
    server_base.cc
    debug.cc
    util.cc
    http.cc
    shared.cc
    tls_server_context_picotls.cc
    tls_server_session_picotls.cc
    tls_session_base_picotls.cc
    tls_shared_picotls.cc
    util_openssl.cc
  )

  set(ptls_INCLUDE_DIRS
    ${CMAKE_SOURCE_DIR}/lib/includes
    ${CMAKE_BINARY_DIR}/lib/includes
    ${CMAKE_SOURCE_DIR}/third-party
    ${CMAKE_SOURCE_DIR}/third-party/urlparse
    ${CMAKE_SOURCE_DIR}/crypto/includes

    ${JEMALLOC_INCLUDE_DIRS}
    ${PICOTLS_INCLUDE_DIRS}
    ${VANILLA_OPENSSL_INCLUDE_DIRS}
    ${LIBEV_INCLUDE_DIRS}
    ${LIBNGHTTP3_INCLUDE_DIRS}
  )

  set(ptls_LIBS
    ngtcp2_crypto_picotls_static
    ngtcp2
    ${JEMALLOC_LIBRARIES}
    ${PICOTLS_LIBRARIES}
    ${VANILLA_OPENSSL_LIBRARIES}
    ${LIBEV_LIBRARIES}
    ${LIBNGHTTP3_LIBRARIES}
  )

  add_executable(ptlsclient ${ptlsclient_SOURCES}
    $<TARGET_OBJECTS:urlparse>
  )
  add_executable(ptlsserver ${ptlsserver_SOURCES}
    $<TARGET_OBJECTS:urlparse>
  )
  set_target_properties(ptlsclient PROPERTIES
    COMPILE_FLAGS "${WARNCXXFLAGS} -DENABLE_EXAMPLE_PICOTLS -DWITH_EXAMPLE_PICOTLS"
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
  )
  set_target_properties(ptlsserver PROPERTIES
    COMPILE_FLAGS "${WARNCXXFLAGS} -DENABLE_EXAMPLE_PICOTLS -DWITH_EXAMPLE_PICOTLS"
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
  )
  target_include_directories(ptlsclient PUBLIC ${ptls_INCLUDE_DIRS})
  target_include_directories(ptlsserver PUBLIC ${ptls_INCLUDE_DIRS})
  target_link_libraries(ptlsclient ${ptls_LIBS})
  target_link_libraries(ptlsserver ${ptls_LIBS})

  # TODO prevent ptlsclient and example ptlsservers from being installed?
endif()

if(LIBEV_FOUND AND HAVE_WOLFSSL AND LIBNGHTTP3_FOUND)
  set(wsslclient_SOURCES
    client.cc
    client_base.cc
    debug.cc
    util.cc
    shared.cc
    tls_client_context_wolfssl.cc
    tls_client_session_wolfssl.cc
    tls_session_base_wolfssl.cc
    util_wolfssl.cc
  )

  set(wsslserver_SOURCES
    server.cc
    server_base.cc
    debug.cc
    util.cc
    http.cc
    shared.cc
    tls_server_context_wolfssl.cc
    tls_server_session_wolfssl.cc
    tls_session_base_wolfssl.cc
    util_wolfssl.cc
  )

  set(wolfssl_INCLUDE_DIRS
    ${CMAKE_SOURCE_DIR}/lib/includes
    ${CMAKE_BINARY_DIR}/lib/includes
    ${CMAKE_SOURCE_DIR}/third-party
    ${CMAKE_SOURCE_DIR}/third-party/urlparse
    ${CMAKE_SOURCE_DIR}/crypto/includes

    ${JEMALLOC_INCLUDE_DIRS}
    ${WOLFSSL_INCLUDE_DIRS}
    ${LIBEV_INCLUDE_DIRS}
    ${LIBNGHTTP3_INCLUDE_DIRS}
  )

  set(wolfssl_LIBS
    ngtcp2_crypto_wolfssl_static
    ngtcp2
    ${JEMALLOC_LIBRARIES}
    ${WOLFSSL_LIBRARIES}
    ${LIBEV_LIBRARIES}
    ${LIBNGHTTP3_LIBRARIES}
  )

  add_executable(wsslclient ${wsslclient_SOURCES}
    $<TARGET_OBJECTS:urlparse>
  )
  add_executable(wsslserver ${wsslserver_SOURCES}
    $<TARGET_OBJECTS:urlparse>
  )
  set_target_properties(wsslclient PROPERTIES
    COMPILE_FLAGS "${WARNCXXFLAGS} -DENABLE_EXAMPLE_WOLFSSL -DWITH_EXAMPLE_WOLFSSL"
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
  )
  set_target_properties(wsslserver PROPERTIES
    COMPILE_FLAGS "${WARNCXXFLAGS} -DENABLE_EXAMPLE_WOLFSSL -DWITH_EXAMPLE_WOLFSSL"
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
  )
  target_include_directories(wsslclient PUBLIC ${wolfssl_INCLUDE_DIRS})
  target_include_directories(wsslserver PUBLIC ${wolfssl_INCLUDE_DIRS})
  target_link_libraries(wsslclient ${wolfssl_LIBS})
  target_link_libraries(wsslserver ${wolfssl_LIBS})

  # TODO prevent wsslclient and example wsslserver from being installed?
endif()
