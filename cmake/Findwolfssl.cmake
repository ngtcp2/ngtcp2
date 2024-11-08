# Try to find wolfssl
# 1. First use CMake find_package if available
# 2. Simulate what find_packge does but with pkg-config

include(FindPackageHandleStandardArgs)
find_package(wolfssl CONFIG)
if (wolfssl_FOUND)
    return()
endif ()

include(FindPkgConfig)
if (wolfssl_FIND_REQUIRED)
    set(wolfssl_FIND_REQUIRED_STR "REQUIRED")
endif()
pkg_check_modules(wolfssl ${wolfssl_FIND_REQUIRED_STR} IMPORTED_TARGET wolfssl)
add_library(wolfssl::wolfssl ALIAS PkgConfig::wolfssl)

# handle the QUIETLY and REQUIRED arguments and set WOLFSSL_FOUND
# to TRUE if all listed variables are TRUE and the requested version
# matches.
find_package_handle_standard_args(wolfssl REQUIRED_VARS
                                  wolfssl_LINK_LIBRARIES wolfssl_INCLUDE_DIRS
                                  VERSION_VAR WOLFSSL_VERSION)
