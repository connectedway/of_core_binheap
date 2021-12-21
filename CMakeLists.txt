cmake_minimum_required(VERSION 3.21.1)
project(of_core_binheap VERSION 1.0.1 DESCRIPTION "OpenFiles Core Binary Heap")

include(configs/default)
configure_file(include/ofh/config.h.in ofh/config.h @ONLY)
include_directories(
	${of_core_BINARY_DIR}
	${of_core_SOURCE_DIR}/include
	${CMAKE_CURRENT_BINARY_DIR})

set(SRCS
    src/binary_heap.c
    )

add_library(of_core_binheap STATIC ${SRCS})

set_target_properties(of_core_binheap PROPERTIES VERSION ${PROJECT_VERSION})
set_target_properties(of_core_binheap PROPERTIES SOVERSION 1)

