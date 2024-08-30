cmake_minimum_required(VERSION 3.10)
project(secp256k1lib CXX)

include_directories(${CMAKE_SOURCE_DIR}/util)

set(SRC_FILES
    secp256k1.cpp
    secp256k1.h
)

# Define the static library target
add_library(${PROJECT_NAME} STATIC ${SRC_FILES})
target_link_libraries(${PROJECT_NAME} PRIVATE util)