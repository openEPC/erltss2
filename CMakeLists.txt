cmake_minimum_required(VERSION 3.15)
project(tpm2_erltss VERSION 0.1 DESCRIPTION "tpm2-tss erlang wrapper")
set(CMAKE_CXX_STANDARD 11)

include(GNUInstallDirs)
include(FindErlang.cmake)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/../priv)

find_library(FAPI_LIB NAMES tss2-fapi)
find_library(MU_LIB NAMES tss2-mu)
find_library(ESYS_LIB NAMES tss2-esys)
find_library(ESYS_RC_LIB NAMES tss2-rc)

set(CMAKE_SHARED_LIBRARY_PREFIX "")
add_library(erlfapi SHARED c_src/erlfapi.cpp c_src/erlfapi.h c_src/util.h c_src/util.cpp)
add_library(erlesys SHARED c_src/erlesys.h c_src/erlesys.cpp c_src/util.h c_src/util.cpp)

target_include_directories(erlfapi PRIVATE ${Erlang_ERTS_INCLUDE_DIRS})
target_include_directories(erlesys PRIVATE ${Erlang_ERTS_INCLUDE_DIRS})

target_link_libraries(erlfapi tss2-fapi ${FAPI_LIB})
target_link_libraries(erlfapi tss2-esys ${ESYS_LIB})
target_link_libraries(erlfapi tss2-mu ${MU_LIB})
target_link_libraries(erlfapi tss2-rc ${ESYS_RC_LIB})

target_link_libraries(erlesys tss2-esys ${ESYS_LIB})
