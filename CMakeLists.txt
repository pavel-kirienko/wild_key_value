# This software is distributed under the terms of the MIT License.
# Copyright (c) Pavel Kirienko.
# Author: Pavel Kirienko <pavel@opencyphal.org>

cmake_minimum_required(VERSION 3.12)
project(wkv_tests C CXX)
enable_testing()

set(CTEST_OUTPUT_ON_FAILURE ON)

# Use -DNO_STATIC_ANALYSIS=1 to suppress static analysis. If not suppressed, the tools used here shall be available.
set(NO_STATIC_ANALYSIS OFF CACHE BOOL "Suppress static analysis tools")
if (NOT NO_STATIC_ANALYSIS)
    find_program(clang_tidy NAMES clang-tidy)
    if (NOT clang_tidy)
        message(FATAL_ERROR "Could not locate clang-tidy")
    endif ()
    message(STATUS "Using clang-tidy: ${clang_tidy}")
    set(CMAKE_CXX_CLANG_TIDY ${clang_tidy})
endif ()

find_program(clang_format NAMES clang-format)
if (NOT clang_format)
    message(STATUS "Could not locate clang-format")
else ()
    file(GLOB format_files
            ${CMAKE_CURRENT_SOURCE_DIR}/*.[ch]pp
            ${CMAKE_CURRENT_SOURCE_DIR}/*.[ch]
    )
    message(STATUS "Using clang-format: ${clang_format}; files: ${format_files}")
    add_custom_target(format COMMAND ${clang_format} -i -fallback-style=none -style=file --verbose ${format_files})
endif ()

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -pedantic -fstrict-aliasing")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wdouble-promotion -Wswitch-enum -Wfloat-equal -Wundef")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wconversion -Wsign-promo")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wsign-conversion -Wcast-align -Wmissing-declarations")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wtype-limits -Wnon-virtual-dtor -Woverloaded-virtual")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-attributes")
if (NOT (CMAKE_CXX_COMPILER_ID STREQUAL "GNU"))
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Werror")
endif ()

# UNITY
add_library(unity STATIC ${CMAKE_CURRENT_SOURCE_DIR}/unity/unity.c)
target_include_directories(unity SYSTEM PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/unity)
target_compile_definitions(unity PUBLIC -DUNITY_SHORTHAND_AS_RAW=1 -DUNITY_OUTPUT_COLOR=1)

# WKV TEST
add_executable(test_wkv ${CMAKE_CURRENT_SOURCE_DIR}/test.cpp)
target_link_libraries(test_wkv unity)
add_test("run_test" "test_wkv")

set(COVERAGE OFF CACHE BOOL "Measure code coverage (may conflict with Clang-Tidy)")
if (COVERAGE)
    message(STATUS "Enabling code coverage")
    target_compile_options(test_wkv PRIVATE --coverage -fcondition-coverage -g -O0)
    target_link_options(test_wkv PRIVATE --coverage)
    target_link_libraries(test_wkv gcov)
    target_compile_definitions(test_wkv PRIVATE WKV_NO_ASSERT=1)
endif()

# BENCHY
add_executable(benchy ${CMAKE_CURRENT_SOURCE_DIR}/benchy.c)
target_link_libraries(benchy m)
add_test("run_benchy" "benchy")

# LCOV REPORT
add_custom_target(lcov
        COMMAND lcov --directory . --capture --output-file coverage.info --mcdc-coverage --branch-coverage
                     --ignore-errors mismatch --ignore-errors corrupt --ignore-errors inconsistent
        COMMAND genhtml coverage.info --output-directory coverage-html --mcdc-coverage --branch-coverage
                        --ignore-errors mismatch --ignore-errors corrupt --ignore-errors inconsistent
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        DEPENDS test_wkv
        COMMENT "+++ COVERAGE REPORT: ${CMAKE_BINARY_DIR}/coverage-html/index.html"
)
