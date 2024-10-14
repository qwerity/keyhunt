####################################################################################################################################################################################
include_directories(${CMAKE_SOURCE_DIR}/)

####################################################################################################################################################################################
set(SRC_FILES
    crypto_util.h
    checksum.cpp
    hash.cpp
    ripemd160.cpp
    rng.cpp
    sha256.cpp
    encryption.cpp

    common.h
    common_host.h

    cuda_util.cpp
    cuda_util.h

    utils.h
    utils.cpp

    address_util.h
    base58.cpp

    secp256k1.cpp
    secp256k1.h
    config.cpp
    config.h

    http_client.cpp
    http_client.h
)

# Define the static library target
add_library(util STATIC ${SRC_FILES})
suppress_msvc_warnings(util)

target_link_libraries(util PRIVATE nlohmann_json::nlohmann_json)
target_link_libraries(util PRIVATE ${Boost_LIBRARIES})
target_link_libraries(util PRIVATE OpenSSL::SSL OpenSSL::Crypto)

####################################################################################################################################################################################