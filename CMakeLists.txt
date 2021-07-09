cmake_minimum_required(VERSION 3.19)
project(cl_signatures C)

set(CMAKE_C_STANDARD 99)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/core/c)

add_library(scheme_A scheme_A/schemeA_signatures.c)
add_library(scheme_B scheme_B/schemeB_signatures.c)

add_executable(test_cl_signatures test_cl_signatures.c)
target_link_libraries(test_cl_signatures scheme_A scheme_B ${CMAKE_CURRENT_SOURCE_DIR}/core/c/core.a)