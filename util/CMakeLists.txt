cmake_minimum_required(VERSION 3.10)
project(util CXX)

set(SRC_FILES
    crypto_util.h
    checksum.cpp
    hash.cpp
    ripemd160.cpp
    rng.cpp
    sha256.cpp

    common.h

    cuda_util.cpp
    cuda_util.h

    utils.h
    utils.cpp
)

# Define the static library target
add_library(${PROJECT_NAME} STATIC ${SRC_FILES})
