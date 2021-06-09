cmake_minimum_required(VERSION 3.16)
project(tpm2_erltss VERSION 0.1 DESCRIPTION "tpm2-tss fapi erlang wrapper")
set(CMAKE_C_STANDARD 11)

include(GNUInstallDirs)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/../priv)

find_library(FAPI_LIB NAMES tss2-fapi)
find_library(MU_LIB NAMES tss2-mu)

add_library(erlfapi SHARED c_src/erlfapi.c c_src/erlfapi.h c_src/util.h c_src/util.c)

target_link_libraries(erlfapi tss2-fapi ${FAPI_LIB})
target_link_libraries(erlfapi tss2-mu ${MU_LIB})