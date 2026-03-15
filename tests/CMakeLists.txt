project(cuda-keyhunt-pvk-tests CXX)

####################################################################################################################################################################################
#suppress_msvc_warnings()

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin/tests)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE}/tests)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG ${CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG}/tests)

####################################################################################################################################################################################
FetchContent_Declare(
    catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG v3.7.0
)
FetchContent_MakeAvailable(catch2)

link_libraries(Catch2::Catch2WithMain)

####################################################################################################################################################################################
link_libraries(util)
link_libraries(Boost::log Boost::log_setup Boost::iostreams)

####################################################################################################################################################################################
if(UNIX)
    find_package(TBB REQUIRED)
endif()

####################################################################################################################################################################################
add_executable(hash_test hash_test.cpp)
target_link_libraries(hash_test PRIVATE nvinfer)
if(UNIX)
    target_link_libraries(hash_test PRIVATE TBB::tbb)
endif()

####################################################################################################################################################################################
add_executable(aes_enc_test aes_enc_test.cpp)

####################################################################################################################################################################################
add_executable(ecc_key_generation_tests ecc_key_generation_tests.cpp)
target_link_libraries(ecc_key_generation_tests PRIVATE nvinfer)

####################################################################################################################################################################################
add_executable(http_client_test http_client_test.cpp)

####################################################################################################################################################################################
add_executable(mnemonic_tests mnemonic_tests.cpp test_data.h)
target_link_libraries(mnemonic_tests PRIVATE util)
target_link_libraries(mnemonic_tests PRIVATE nvinfer)
target_link_libraries(mnemonic_tests PRIVATE wallycore secp256k1)

####################################################################################################################################################################################
add_test(NAME hash_test COMMAND hash_test)
add_test(NAME private_key_generation_tests COMMAND private_key_generation_tests)
add_test(NAME http_client_test COMMAND http_client_test)
add_test(NAME mnemonic_tests COMMAND mnemonic_tests)

####################################################################################################################################################################################
####################################################################################################################################################################################
add_executable(cuda_secp256k1_v2_test cuda_secp256k1_v2_test.cu)
target_link_libraries(cuda_secp256k1_v2_test PRIVATE util)
target_link_libraries(cuda_secp256k1_v2_test PRIVATE nvinfer)
set_target_properties(cuda_secp256k1_v2_test PROPERTIES
    CUDA_RESOLVE_DEVICE_SYMBOLS ON
    CUDA_SEPARABLE_COMPILATION ON
)

####################################################################################################################################################################################
add_executable(generate_private_key_test generate_private_key_test.cu)
target_link_libraries(generate_private_key_test PRIVATE util)
target_link_libraries(generate_private_key_test PRIVATE nvinfer)
set_target_properties(generate_private_key_test PROPERTIES
    CUDA_RESOLVE_DEVICE_SYMBOLS ON
    CUDA_SEPARABLE_COMPILATION ON
)

add_test(NAME generate_private_key_test COMMAND generate_private_key_test)

####################################################################################################################################################################################
add_executable(hash160_file_test hash160_file_test.cpp)
target_link_libraries(hash160_file_test PRIVATE util)
target_link_libraries(hash160_file_test PRIVATE Boost::log Boost::log_setup Boost::iostreams)
add_test(NAME hash160_file_test COMMAND hash160_file_test)

####################################################################################################################################################################################
# Прямая проверка gpuHash160Comp / gpuHash160Uncomp (порядок байт)
add_executable(gpu_hash160_test gpu_hash160_test.cu)
target_link_libraries(gpu_hash160_test PRIVATE util nvinfer)
set_target_properties(gpu_hash160_test PROPERTIES
    CUDA_RESOLVE_DEVICE_SYMBOLS ON
    CUDA_SEPARABLE_COMPILATION ON
)
add_test(NAME gpu_hash160_test COMMAND gpu_hash160_test)

####################################################################################################################################################################################
