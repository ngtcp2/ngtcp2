#----------------------------------------------------------------
# Generated CMake target import file for configuration "RelWithDebInfo".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "ngtcp2::ngtcp2" for configuration "RelWithDebInfo"
set_property(TARGET ngtcp2::ngtcp2 APPEND PROPERTY IMPORTED_CONFIGURATIONS RELWITHDEBINFO)
set_target_properties(ngtcp2::ngtcp2 PROPERTIES
  IMPORTED_LOCATION_RELWITHDEBINFO "${_IMPORT_PREFIX}/lib/libngtcp2.so.16.7.0"
  IMPORTED_SONAME_RELWITHDEBINFO "libngtcp2.so.16"
  )

list(APPEND _cmake_import_check_targets ngtcp2::ngtcp2 )
list(APPEND _cmake_import_check_files_for_ngtcp2::ngtcp2 "${_IMPORT_PREFIX}/lib/libngtcp2.so.16.7.0" )

# Import target "ngtcp2::ngtcp2_static" for configuration "RelWithDebInfo"
set_property(TARGET ngtcp2::ngtcp2_static APPEND PROPERTY IMPORTED_CONFIGURATIONS RELWITHDEBINFO)
set_target_properties(ngtcp2::ngtcp2_static PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELWITHDEBINFO "C"
  IMPORTED_LOCATION_RELWITHDEBINFO "${_IMPORT_PREFIX}/lib/libngtcp2.a"
  )

list(APPEND _cmake_import_check_targets ngtcp2::ngtcp2_static )
list(APPEND _cmake_import_check_files_for_ngtcp2::ngtcp2_static "${_IMPORT_PREFIX}/lib/libngtcp2.a" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
