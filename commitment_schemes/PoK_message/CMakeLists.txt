cmake_minimum_required(VERSION 3.19)
project(cl_signatures C)

set(CMAKE_C_STANDARD 99)

include_directories(${CMAKE_SOURCE_DIR}/core/c)

add_library(PoK_message PoK_message.c)