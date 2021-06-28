cmake_minimum_required(VERSION 3.15)
project(tpm2_erltss VERSION 0.1 DESCRIPTION "tpm2-tss fapi erlang wrapper")
set(CMAKE_CXX_STANDARD 11)

include(GNUInstallDirs)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/../priv)

find_library(FAPI_LIB NAMES tss2-fapi)
find_library(MU_LIB NAMES tss2-mu)
find_library(ESYS_LIB NAMES tss2-esys)

set(CMAKE_SHARED_LIBRARY_PREFIX "")
add_library(erlfapi SHARED c_src/erlfapi.cpp c_src/erlfapi.h c_src/util.h c_src/util.cpp)

target_link_libraries(erlfapi tss2-fapi ${FAPI_LIB})
target_link_libraries(erlfapi tss2-esys ${ESYS_LIB})
target_link_libraries(erlfapi tss2-mu ${MU_LIB})
