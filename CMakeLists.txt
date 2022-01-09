cmake_minimum_required(VERSION 3.20.0)
project(of_core_binheap VERSION 1.0.1 DESCRIPTION "OpenFiles Core Binary Heap")

include(configs/default)
configure_file(include/ofh/config.h.in ofh/config.h @ONLY)
include_directories(
        ${of_core_SOURCE_DIR}/include
        ${CMAKE_CURRENT_BINARY_DIR})

set(SRCS
        src/binary_heap.c
        )

add_library(of_core_binheap OBJECT ${SRCS})
set_property(TARGET of_core_binheap PROPERTY POSITION_INDEPENDENT_CODE ON)
