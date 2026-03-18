####################################################################################################################################################################################
suppress_msvc_warnings()

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
    sha1.cpp
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

    xpart_manager.cpp
    xpart_manager.h

    bitcoin_utils.cpp
    bitcoin_utils.h

    results_processor.cpp
    results_processor.h
)

# Define the static library target
add_library(util STATIC ${SRC_FILES})

target_link_libraries(util PRIVATE nlohmann_json::nlohmann_json)
target_link_libraries(util PRIVATE Boost::log Boost::iostreams)
target_link_libraries(util PRIVATE OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(util PRIVATE wallycore secp256k1)
target_link_libraries(util PUBLIC CUDA::cudart_static)

####################################################################################################################################################################################
