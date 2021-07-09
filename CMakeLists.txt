cmake_minimum_required(VERSION 3.19)
project(cl_signatures C)

set(CMAKE_C_STANDARD 99)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/core/c)

add_library(scheme_A scheme_A/schemeA_signatures.c)
add_library(scheme_B scheme_B/schemeB_signatures.c)

add_executable(test_schemeA test_scheme_A.c)
target_link_libraries(test_schemeA scheme_A ${CMAKE_CURRENT_SOURCE_DIR}/core/c/core.a)

add_executable(test_schemeB test_scheme_B.c)
target_link_libraries(test_schemeB scheme_B ${CMAKE_CURRENT_SOURCE_DIR}/core/c/core.a)