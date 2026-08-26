# Try to find wolfssl
# 1. First use CMake find_package if available
# 2. Simulate what find_packge does but with pkg-config

find_package(wolfssl CONFIG)
if (wolfssl_FOUND)
    set(WOLFSSL_LINK_TARGET wolfssl::wolfssl)
    return()
endif ()

find_package(PkgConfig QUIET)
if (wolfssl_FIND_REQUIRED)
    set(wolfssl_FIND_REQUIRED_STR "REQUIRED")
endif()
pkg_check_modules(PC_WOLFSSL ${wolfssl_FIND_REQUIRED_STR} wolfssl)

find_path(WOLFSSL_INCLUDE_DIR
  NAMES wolfssl/ssl.h
  HINTS ${PC_WOLFSSL_INCLUDE_DIRS}
)
find_library(WOLFSSL_LIBRARY
  NAMES wolfssl
  HINTS ${PC_WOLFSSL_LIBRARY_DIRS}
)

if(WOLFSSL_INCLUDE_DIR)
  set(_version_regex "^#define[ \t]+LIBWOLFSSL_VERSION_STRING[ \t]+\"([^\"]+)\".*")
  file(STRINGS "${WOLFSSL_INCLUDE_DIR}/wolfssl/version.h"
    WOLFSSL_VERSION REGEX "${_version_regex}")
  string(REGEX REPLACE "${_version_regex}" "\\1"
    WOLFSSL_VERSION "${WOLFSSL_VERSION}")
  unset(_version_regex)
endif()

add_library(wolfssl::wolfssl INTERFACE IMPORTED)

set_target_properties(wolfssl::wolfssl PROPERTIES
  INTERFACE_INCLUDE_DIRECTORIES ${WOLFSSL_INCLUDE_DIR}
  INTERFACE_LINK_LIBRARIES ${WOLFSSL_LIBRARY}
)

# We found wolfSSL built with autotools, which doesn't have
# proper CMake Config usable in find_package directy. When we
# exporting our own targets depending on wolfSSL we don't want them
# to declare dependency on wolfssl::wolfssl because any consumers of
# it won't be able to discover it without repeating what we have done here.
set(WOLFSSL_LINK_TARGET $<BUILD_INTERFACE:wolfssl::wolfssl>)


include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set WOLFSSL_FOUND
# to TRUE if all listed variables are TRUE and the requested version
# matches.
find_package_handle_standard_args(wolfssl REQUIRED_VARS
                                  WOLFSSL_LIBRARY WOLFSSL_INCLUDE_DIR
                                  VERSION_VAR WOLFSSL_VERSION)
