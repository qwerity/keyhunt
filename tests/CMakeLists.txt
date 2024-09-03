cmake_minimum_required(VERSION 3.29)
project(cuda-keyhunt-pvk-tests CXX)

####################################################################################################################################################################################
include(FetchContent)
FetchContent_Declare(
    catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG v3.7.0
)
FetchContent_MakeAvailable(catch2)

####################################################################################################################################################################################
find_package(TBB REQUIRED)

####################################################################################################################################################################################
include_directories(${CMAKE_SOURCE_DIR}/util)

####################################################################################################################################################################################
add_executable(hash_test
    hash_test.cpp
)
target_link_libraries(hash_test PUBLIC util)
target_link_libraries(hash_test PRIVATE TBB::tbb)
target_link_libraries(hash_test PRIVATE Catch2::Catch2WithMain)
add_test(NAME hash_test COMMAND MyTests)

####################################################################################################################################################################################