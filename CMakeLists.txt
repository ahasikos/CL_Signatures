cmake_minimum_required(VERSION 3.19)
project(cl_signatures C)

set(CMAKE_C_STANDARD 99)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/core/c)
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

add_library(scheme_A scheme_A/schemeA_signatures.c)
add_library(scheme_B scheme_B/schemeB_signatures.c)
add_library(scheme_C scheme_C/schemeC_signatures.c)
add_library(scheme_D scheme_D/schemeD_signatures.c)
add_library(signature_on_committed_value
        signature_on_committed_value/commitment_scheme.c
        signature_on_committed_value/sign_commitment.c
        signature_on_committed_value/signature_PoK.c)
add_library(utils utils/utils.c)

add_executable(test_cl_signatures test_cl_signatures.c)
target_link_libraries(test_cl_signatures utils scheme_A scheme_B scheme_C scheme_D ${CMAKE_CURRENT_SOURCE_DIR}/core/c/core.a)

add_executable(test_zkPoK test_zkPoK.c)
target_link_libraries(test_zkPoK signature_on_committed_value scheme_C scheme_D utils ${CMAKE_CURRENT_SOURCE_DIR}/core/c/core.a)

add_executable(test_anonymous_credentials test_anonymous_credentials.c)
target_link_libraries(test_anonymous_credentials utils scheme_D signature_on_committed_value ${CMAKE_CURRENT_SOURCE_DIR}/core/c/core.a)