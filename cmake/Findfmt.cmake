# - Try to find fmt
# Once done this will define
#  FMT_FOUND        - System has fmt
#  FMT_INCLUDE_DIRS - The fmt include directories
#  FMT_LIBRARIES    - The libraries needed to use fmt

find_package(PkgConfig QUIET)
pkg_check_modules(PC_FMT QUIET fmt)

find_path(FMT_INCLUDE_DIR
  NAMES fmt/core.h
  HINTS ${PC_FMT_INCLUDE_DIRS}
)
find_library(FMT_LIBRARY
  NAMES fmt
  HINTS ${PC_FMT_LIBRARY_DIRS}
)

if(PC_FMT_FOUND)
  set(FMT_VERSION ${PC_FMT_VERSION})
endif()

include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set FMT_FOUND to TRUE
# if all listed variables are TRUE and the requested version matches.
find_package_handle_standard_args(fmt REQUIRED_VARS
                                  FMT_LIBRARY FMT_INCLUDE_DIR
                                  VERSION_VAR FMT_VERSION)

if(FMT_FOUND)
  set(FMT_LIBRARIES     ${FMT_LIBRARY})
  set(FMT_INCLUDE_DIRS  ${FMT_INCLUDE_DIR})
endif()

mark_as_advanced(FMT_INCLUDE_DIR FMT_LIBRARY)
