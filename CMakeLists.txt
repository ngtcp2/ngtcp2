# ngtcp2
#
# Copyright (c) 2016 ngtcp2 contributors
# Copyright (c) 2012 nghttp2 contributors
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

cmake_minimum_required(VERSION 3.1)

# Allow setting VISIBILITY_PRESET on static library targets without warning.
cmake_policy(SET CMP0063 NEW)

# XXX using 0.1.90 instead of 0.1.0-DEV
project(ngtcp2 VERSION 0.1.90)

# See versioning rule:
#  http://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html
set(LT_CURRENT  0)
set(LT_REVISION 0)
set(LT_AGE      0)

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake" "${CMAKE_MODULE_PATH}")
include(Version)

math(EXPR LT_SOVERSION "${LT_CURRENT} - ${LT_AGE}")
set(LT_VERSION "${LT_SOVERSION}.${LT_AGE}.${LT_REVISION}")
set(PACKAGE_VERSION     "${PROJECT_VERSION}")
HexVersion(PACKAGE_VERSION_NUM ${PROJECT_VERSION_MAJOR} ${PROJECT_VERSION_MINOR} ${PROJECT_VERSION_PATCH})

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "Choose the build type" FORCE)

  # Include "None" as option to disable any additional (optimization) flags,
  # relying on just CMAKE_C_FLAGS and CMAKE_CXX_FLAGS (which are empty by
  # default). These strings are presented in cmake-gui.
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
    "None" "Debug" "Release" "MinSizeRel" "RelWithDebInfo")
endif()

include(GNUInstallDirs)

include(CMakeOptions.txt)

# Do not disable assertions based on CMAKE_BUILD_TYPE.
foreach(_build_type "Release" "MinSizeRel" "RelWithDebInfo")
  foreach(_lang C CXX)
    string(TOUPPER "CMAKE_${_lang}_FLAGS_${_build_type}" _var)
    string(REGEX REPLACE "(^| )[/-]D *NDEBUG($| )" "" ${_var} "${${_var}}")
  endforeach()
endforeach()


if(WITHOUT_GNUTLS)
  set(GNUTLS_FOUND FALSE)
else()
  find_package(GnuTLS 3.6.12)
endif()
if(WITHOUT_OPENSSL)
  set(OPENSSL_FOUND FALSE)
else()
  find_package(OpenSSL 1.1.1)
endif()
find_package(Libev 4.11)
find_package(Libnghttp3 0.0.0)
find_package(CUnit 2.1)
enable_testing()
set(HAVE_CUNIT      ${CUNIT_FOUND})
if(HAVE_CUNIT)
  add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND})
endif()

# openssl (for examples)
set(HAVE_OPENSSL    ${OPENSSL_FOUND})
if(OPENSSL_FOUND)
  set(OPENSSL_INCLUDE_DIRS  ${OPENSSL_INCLUDE_DIR})
  set(HAVE_CRYPTO 1)
else()
  set(OPENSSL_INCLUDE_DIRS  "")
  set(OPENSSL_LIBRARIES     "")
endif()
# libev (for examples)
set(HAVE_LIBEV      ${LIBEV_FOUND})
# libnghttp3 (for examples)
set(HAVE_LIBNGHTTP3 ${LIBNGHTTP3_FOUND})

# GnuTLS (for examples)
set(HAVE_GNUTLS    ${GNUTLS_FOUND})
if(GNUTLS_FOUND)
  set(GNUTLS_INCLUDE_DIRS  ${GNUTLS_INCLUDE_DIR})
  set(HAVE_CRYPTO 1)
else()
  set(GNUTLS_INCLUDE_DIRS  "")
  set(GNUTLS_LIBRARIES     "")
endif()

# Checks for header files.
include(CheckIncludeFile)
check_include_file("arpa/inet.h"   HAVE_ARPA_INET_H)
check_include_file("netinet/in.h"  HAVE_NETINET_IN_H)
check_include_file("stddef.h"      HAVE_STDDEF_H)
check_include_file("stdint.h"      HAVE_STDINT_H)
check_include_file("stdlib.h"      HAVE_STDLIB_H)
check_include_file("string.h"      HAVE_STRING_H)
check_include_file("unistd.h"      HAVE_UNISTD_H)
check_include_file("sys/endian.h"  HAVE_SYS_ENDIAN_H)
check_include_file("endian.h"      HAVE_ENDIAN_H)

include(CheckTypeSize)
# Checks for typedefs, structures, and compiler characteristics.
# AC_TYPE_SIZE_T
check_type_size("ssize_t" SIZEOF_SSIZE_T)
if(SIZEOF_SSIZE_T STREQUAL "")
  # ssize_t is a signed type in POSIX storing at least -1.
  # Set it to a pointer-size int.
  set(ssize_t ptrdiff_t)
endif()

# Checks for symbols.
include(CheckSymbolExists)
if(HAVE_ENDIAN_H)
  check_symbol_exists(be64toh "endian.h" HAVE_BE64TOH)
endif()
if(HAVE_SYS_ENDIAN_H)
  check_symbol_exists(be64toh "sys/endian.h" HAVE_BE64TOH)
endif()

include(ExtractValidFlags)
set(WARNCFLAGS)
set(WARNCXXFLAGS)
if(CMAKE_C_COMPILER_ID MATCHES "MSVC")
  if(ENABLE_WERROR)
    set(WARNCFLAGS    /WX)
    set(WARNCXXFLAGS  /WX)
  endif()
else()
  if(ENABLE_WERROR)
    extract_valid_c_flags(WARNCFLAGS    -Werror)
    extract_valid_c_flags(WARNCXXFLAGS  -Werror)
  endif()

  # For C compiler
  extract_valid_c_flags(WARNCFLAGS
    -Wall
    -Wextra
    -Wmissing-prototypes
    -Wstrict-prototypes
    -Wmissing-declarations
    -Wpointer-arith
    -Wdeclaration-after-statement
    -Wformat-security
    -Wwrite-strings
    -Wshadow
    -Winline
    -Wnested-externs
    -Wfloat-equal
    -Wundef
    -Wendif-labels
    -Wempty-body
    -Wcast-align
    -Wclobbered
    -Wvla
    -Wpragmas
    -Wunreachable-code
    -Waddress
    -Wattributes
    -Wdiv-by-zero
    -Wshorten-64-to-32

    -Wconversion
    -Wextended-offsetof
    -Wformat-nonliteral
    -Wlanguage-extension-token
    -Wmissing-field-initializers
    -Wmissing-noreturn
    -Wmissing-variable-declarations
    # Not used because we cannot change public structs
    # -Wpadded
    -Wsign-conversion
    # Not used because this basically disallows default case
    # -Wswitch-enum
    -Wunreachable-code-break
    -Wunused-macros
    -Wunused-parameter
    -Wredundant-decls
    # Only work with Clang for the moment
    -Wheader-guard
    -Wsometimes-uninitialized

    # Only work with gcc7 for the moment
    -Wduplicated-branches
    # This is required because we pass format string as "const char*.
    -Wno-format-nonliteral
  )

  extract_valid_cxx_flags(WARNCXXFLAGS
    # For C++ compiler
    -Wall
    -Wformat-security
    -Wsometimes-uninitialized
    # Disable noexcept-type warning of g++-7.  This is not harmful as
    # long as all source files are compiled with the same compiler.
    -Wno-noexcept-type
  )

  if(ENABLE_ASAN)
    include(CMakePushCheckState)
    cmake_push_check_state()
    set(CMAKE_REQUIRED_LIBRARIES "-fsanitize=address")
    check_c_compiler_flag(-fsanitize=address C__fsanitize_address_VALID)
    check_cxx_compiler_flag(-fsanitize=address CXX__fsanitize_address_VALID)
    cmake_pop_check_state()
    if(NOT C__fsanitize_address_VALID OR NOT CXX__fsanitize_address_VALID)
      message(WARNING "ENABLE_ASAN was requested, but not supported!")
    else()
      set(CMAKE_C_FLAGS "-fsanitize=address ${CMAKE_C_FLAGS}")
      set(CMAKE_CXX_FLAGS "-fsanitize=address ${CMAKE_CXX_FLAGS}")
    endif()
  endif()
endif()

if(ENABLE_DEBUG)
  set(DEBUGBUILD 1)
endif()

add_definitions(-DHAVE_CONFIG_H)
configure_file(cmakeconfig.h.in config.h)
# autotools-compatible names
# Sphinx expects relative paths in the .rst files. Use the fact that the files
# below are all one directory level deep.
file(RELATIVE_PATH top_srcdir   "${CMAKE_CURRENT_BINARY_DIR}/dir" "${CMAKE_CURRENT_SOURCE_DIR}")
file(RELATIVE_PATH top_builddir "${CMAKE_CURRENT_BINARY_DIR}/dir" "${CMAKE_CURRENT_BINARY_DIR}")
set(abs_top_srcdir  "${CMAKE_CURRENT_SOURCE_DIR}")
set(abs_top_builddir "${CMAKE_CURRENT_BINARY_DIR}")
# libngtcp2.pc (pkg-config file)
set(prefix          "${CMAKE_INSTALL_PREFIX}")
set(exec_prefix     "${CMAKE_INSTALL_PREFIX}")
set(libdir          "${CMAKE_INSTALL_FULL_LIBDIR}")
set(includedir      "${CMAKE_INSTALL_FULL_INCLUDEDIR}")
set(VERSION         "${PACKAGE_VERSION}")
# For init scripts and systemd service file (in contrib/)
set(bindir          "${CMAKE_INSTALL_FULL_BINDIR}")
set(sbindir         "${CMAKE_INSTALL_FULL_SBINDIR}")
foreach(name
  lib/libngtcp2.pc
  lib/includes/ngtcp2/version.h
)
  configure_file("${name}.in" "${name}" @ONLY)
endforeach()

include_directories(
  "${CMAKE_CURRENT_BINARY_DIR}" # for config.h
)
# For use in src/CMakeLists.txt
set(PKGDATADIR "${CMAKE_INSTALL_FULL_DATADIR}/${CMAKE_PROJECT_NAME}")

install(FILES README.rst DESTINATION "${CMAKE_INSTALL_DOCDIR}")

add_subdirectory(lib)
add_subdirectory(tests)
add_subdirectory(crypto)
add_subdirectory(third-party)
add_subdirectory(examples)


string(TOUPPER "${CMAKE_BUILD_TYPE}" _build_type)
message(STATUS "summary of build options:

    Package version: ${VERSION}
    Library version: ${LT_CURRENT}:${LT_REVISION}:${LT_AGE}
    Install prefix:  ${CMAKE_INSTALL_PREFIX}
    Target system:   ${CMAKE_SYSTEM_NAME}
    Compiler:
      Build type:     ${CMAKE_BUILD_TYPE}
      C compiler:     ${CMAKE_C_COMPILER}
      CFLAGS:         ${CMAKE_C_FLAGS_${_build_type}} ${CMAKE_C_FLAGS}
      C++ compiler:   ${CMAKE_CXX_COMPILER}
      CXXFLAGS:       ${CMAKE_CXX_FLAGS_${_build_type}} ${CMAKE_CXX_FLAGS}
      WARNCFLAGS:     ${WARNCFLAGS}
      WARNCXXFLAGS:   ${WARNCXXFLAGS}
    Test:
      CUnit:          ${HAVE_CUNIT} (LIBS='${CUNIT_LIBRARIES}')
    Libs:
      OpenSSL:        ${HAVE_OPENSSL} (LIBS='${OPENSSL_LIBRARIES}')
      Libev:          ${HAVE_LIBEV} (LIBS='${LIBEV_LIBRARIES}')
      Libnghttp3:     ${HAVE_LIBNGHTTP3} (LIBS='${LIBNGHTTP3_LIBRARIES}')
      GnuTLS:         ${HAVE_GNUTLS} (LIBS='${GNUTLS_LIBRARIES}')
")
