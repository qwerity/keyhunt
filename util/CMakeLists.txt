cmake_minimum_required(VERSION 3.10)

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

    address_util.h
    base58.cpp

    secp256k1.cpp
    secp256k1.h
)

# Define the static library target
add_library(util STATIC ${SRC_FILES})
target_link_libraries(util PRIVATE ${Boost_LIBRARIES})
