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
add_subdirectory(commitment_schemes/PoK_signature)

add_subdirectory(sign_commitment)

add_subdirectory(utils)


add_executable(test_cl_signatures test_cl_signatures.c)
target_link_libraries(test_cl_signatures
        utils
        schemeA
        schemeB
        schemeC
        schemeD
        ${CMAKE_CURRENT_SOURCE_DIR}/core/c/core.a)

add_executable(test_zkPoK test_anonymous_credentials.c)
target_link_libraries(test_zkPoK
        PoK_message
        PoK_signature
        sign_commitment
        schemeD
        utils
        ${CMAKE_CURRENT_SOURCE_DIR}/core/c/core.a)
