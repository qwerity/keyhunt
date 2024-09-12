cmake_minimum_required(VERSION 3.29)
project(cuda-keyhunt-pvk CXX CUDA)

####################################################################################################################################################################################
include(FetchContent)

####################################################################################################################################################################################
# Set the C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

####################################################################################################################################################################################
option(BUILD_TESTS "Build test_bitcoin executable." OFF)

####################################################################################################################################################################################
find_package(Boost 1.80 REQUIRED COMPONENTS system log_setup log program_options)

include_directories(${Boost_INCLUDE_DIRS})

####################################################################################################################################################################################
# Set compiler options
# Set the C++ compiler flags for Debug and Release configurations
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -Wall -Wextra")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG -Wall")
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "-O2 -g -Wall")

####################################################################################################################################################################################
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

####################################################################################################################################################################################
add_subdirectory(util)
add_subdirectory(cuda)

####################################################################################################################################################################################
set(MAIN_SRC
    main.cpp
    key_hunter.cpp
    key_hunter.h
    key_processor.cpp
    key_processor.h
)
add_executable(${PROJECT_NAME} ${MAIN_SRC})
target_link_libraries(${PROJECT_NAME} PRIVATE util)
target_link_libraries(${PROJECT_NAME} PRIVATE cuda_keys)
target_link_libraries(${PROJECT_NAME} PRIVATE ${Boost_LIBRARIES})

# TESTS ############################################################################################################################################################################
if(BUILD_TESTS)
    add_subdirectory(tests)

    enable_testing()
endif()

####################################################################################################################################################################################