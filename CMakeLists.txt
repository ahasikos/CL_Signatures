cmake_minimum_required(VERSION 3.19)
project(cl_signatures C)

set(CMAKE_C_STANDARD 99)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/core/c)
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

add_subdirectory(signatures/schemeA)
add_subdirectory(signatures/schemeB)
add_subdirectory(signatures/schemeC)
add_subdirectory(signatures/schemeD)

add_subdirectory(commitment_schemes/PoK_message)

add_library(signature_on_committed_value
        signature_on_committed_value/sign_commitment.c
        signature_on_committed_value/signature_PoK.c)
add_library(utils utils/utils.c)

add_executable(test_cl_signatures test_cl_signatures.c)
target_link_libraries(test_cl_signatures utils schemeA schemeB schemeC schemeD ${CMAKE_CURRENT_SOURCE_DIR}/core/c/core.a)

add_executable(test_zkPoK test_zkPoK.c)
target_link_libraries(test_zkPoK PoK_message signature_on_committed_value schemeC schemeD utils ${CMAKE_CURRENT_SOURCE_DIR}/core/c/core.a)

add_executable(test_anonymous_credentials test_anonymous_credentials.c)
target_link_libraries(test_anonymous_credentials utils schemeD signature_on_committed_value ${CMAKE_CURRENT_SOURCE_DIR}/core/c/core.a)