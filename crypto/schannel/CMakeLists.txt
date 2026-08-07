# ngtcp2

# Copyright (c) 2026 ngtcp2 contributors

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

add_definitions(-DBUILDING_NGTCP2 -DSECURITY_WIN32)

set(ngtcp2_crypto_schannel_SOURCES
  schannel_crypto.c
  schannel_tls.c
  ../shared.c
)

set(ngtcp2_crypto_schannel_INCLUDE_DIRS
  "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/lib>"
  "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/crypto/includes>"
  "$<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/crypto/includes>"
  "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/crypto>"
  "$<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/crypto>"
  "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
)

set(ngtcp2_crypto_schannel_LIBS secur32 bcrypt)

configure_file(libngtcp2_crypto_schannel.pc.in
               libngtcp2_crypto_schannel.pc @ONLY)

if(ENABLE_SHARED_LIB)
  add_library(ngtcp2_crypto_schannel SHARED
    ${ngtcp2_crypto_schannel_SOURCES})
  set_target_properties(ngtcp2_crypto_schannel PROPERTIES
    COMPILE_FLAGS "${WARNCFLAGS}"
    VERSION ${CRYPTO_SCHANNEL_LT_VERSION}
    SOVERSION ${CRYPTO_SCHANNEL_LT_SOVERSION}
    C_VISIBILITY_PRESET hidden
    POSITION_INDEPENDENT_CODE ON
  )
  target_include_directories(ngtcp2_crypto_schannel PUBLIC
    ${ngtcp2_crypto_schannel_INCLUDE_DIRS})
  target_link_libraries(ngtcp2_crypto_schannel PUBLIC ngtcp2
    ${ngtcp2_crypto_schannel_LIBS})

  install(TARGETS ngtcp2_crypto_schannel
    EXPORT "${PROJECT_NAME}Targets"
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
endif()

if(ENABLE_STATIC_LIB)
  add_library(ngtcp2_crypto_schannel_static STATIC
    ${ngtcp2_crypto_schannel_SOURCES})
  set_target_properties(ngtcp2_crypto_schannel_static PROPERTIES
    COMPILE_FLAGS "${WARNCFLAGS}"
    VERSION ${CRYPTO_SCHANNEL_LT_VERSION}
    SOVERSION ${CRYPTO_SCHANNEL_LT_SOVERSION}
    ARCHIVE_OUTPUT_NAME ngtcp2_crypto_schannel${STATIC_LIB_SUFFIX}
    C_VISIBILITY_PRESET hidden
  )
  target_compile_definitions(ngtcp2_crypto_schannel_static PUBLIC
    NGTCP2_STATICLIB)
  target_include_directories(ngtcp2_crypto_schannel_static PUBLIC
    ${ngtcp2_crypto_schannel_INCLUDE_DIRS})
  target_link_libraries(ngtcp2_crypto_schannel_static PUBLIC ngtcp2_static
    ${ngtcp2_crypto_schannel_LIBS})

  install(TARGETS ngtcp2_crypto_schannel_static
    EXPORT "${PROJECT_NAME}Targets"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}")
endif()

if(BUILD_TESTING AND ENABLE_STATIC_LIB)
  find_program(POWERSHELL_EXECUTABLE NAMES powershell pwsh REQUIRED)
  add_executable(schannel_cryptotest EXCLUDE_FROM_ALL
    ../cryptotest.c
    ../shared_test.c
    schannel_test.c
    ${PROJECT_SOURCE_DIR}/tests/munit/munit.c)
  target_compile_definitions(schannel_cryptotest PRIVATE
    WITH_SCHANNEL_TESTS)
  target_include_directories(schannel_cryptotest PRIVATE
    ${ngtcp2_crypto_schannel_INCLUDE_DIRS}
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${PROJECT_SOURCE_DIR}/tests/munit)
  target_link_libraries(schannel_cryptotest
    ngtcp2_crypto_schannel_static ngtcp2_static crypt32 ws2_32)
  add_test(NAME schannel_cryptotest
    COMMAND ${POWERSHELL_EXECUTABLE} -NoProfile -ExecutionPolicy Bypass
      -File ${CMAKE_CURRENT_SOURCE_DIR}/run_schannel_test.ps1
      -TestExecutable $<TARGET_FILE:schannel_cryptotest>)
  add_dependencies(check schannel_cryptotest)
endif()

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/libngtcp2_crypto_schannel.pc"
  DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")
