####################################################################################################################################################################################
FetchContent_Declare(
    json
    URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
)
FetchContent_MakeAvailable(json)

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

    common.h

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
)

# Define the static library target
add_library(util STATIC ${SRC_FILES})
target_link_libraries(util PRIVATE nlohmann_json::nlohmann_json)
target_link_libraries(util PRIVATE ${Boost_LIBRARIES})

####################################################################################################################################################################################