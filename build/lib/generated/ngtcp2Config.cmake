include(CMakeFindDependencyMacro)
if("FALSE")
    find_dependency(OpenSSL)
endif()

include("${CMAKE_CURRENT_LIST_DIR}/ngtcp2Targets.cmake")
