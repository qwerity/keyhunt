project(cuda-keyhunt-pvk-tests CXX)

####################################################################################################################################################################################
FetchContent_Declare(
    catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG v3.7.0
)
FetchContent_MakeAvailable(catch2)

####################################################################################################################################################################################
if(UNIX)
    find_package(TBB REQUIRED)
endif()
find_package(OpenSSL 3 REQUIRED)

####################################################################################################################################################################################
add_executable(hash_test
    hash_test.cpp
    private_key_generation_tests.cpp
)
target_link_libraries(hash_test PRIVATE util)
target_link_libraries(hash_test PRIVATE cuda_keys)
target_link_libraries(hash_test PRIVATE Catch2::Catch2WithMain)
target_link_libraries(hash_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)
if(UNIX)
    target_link_libraries(hash_test PRIVATE TBB::tbb)
endif()

####################################################################################################################################################################################
add_executable(private_key_generation_tests
    private_key_generation_tests.cpp
)
target_link_libraries(private_key_generation_tests PRIVATE util cuda_keys)
target_link_libraries(private_key_generation_tests PRIVATE Catch2::Catch2WithMain)
target_link_libraries(private_key_generation_tests PRIVATE ${Boost_LIBRARIES})

####################################################################################################################################################################################
add_test(NAME hash_test COMMAND hash_test)
add_test(NAME private_key_generation_tests COMMAND private_key_generation_tests)

####################################################################################################################################################################################