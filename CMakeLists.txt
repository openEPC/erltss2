cmake_minimum_required(VERSION 3.19)
project(tpm2_erltss)

set(CMAKE_C_STANDARD 11)

find_library(FAPI_LIB NAMES tss2-fapi)
find_library(MU_LIB NAMES tss2-mu)

add_library(erlfapi SHARED src/erlfapi.cpp src/erlfapi.h src/util.h src/util.cpp)

target_link_libraries(erlfapi tss2-fapi ${FAPI_LIB})
target_link_libraries(erlfapi tss2-mu ${MU_LIB})

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/src/erlfapi.erl ${CMAKE_CURRENT_BINARY_DIR}/erlfapi.erl COPYONLY)

#add_custom_command(
#        TARGET erlfapi POST_BUILD
#        COMMAND ${CMAKE_COMMAND} -E copy
#        ${CMAKE_CURRENT_SOURCE_DIR}/src/erlfapi.erl
#        ${CMAKE_CURRENT_BINARY_DIR}/erlfapi.erl)