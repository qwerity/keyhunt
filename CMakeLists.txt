cmake_minimum_required(VERSION 3.29)
project(cuda-keyhunt-pvk CXX CUDA)

####################################################################################################################################################################################
# Set the C++ standard
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

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
add_subdirectory(secp256k1lib)
add_subdirectory(util)
add_subdirectory(cuda)

####################################################################################################################################################################################
include_directories(secp256k1lib)

set(MAIN_SRC
    main.cpp
    key_generator.cpp
    key_generator.h
    util/common.h
    key_processor.cpp
    key_processor.h
)
add_executable(cuda-keyhunt-pvk ${MAIN_SRC})
target_link_libraries(cuda-keyhunt-pvk PUBLIC secp256k1lib)
target_link_libraries(cuda-keyhunt-pvk PUBLIC util)
target_link_libraries(cuda-keyhunt-pvk PUBLIC cuda_keys)
target_link_libraries(cuda-keyhunt-pvk PUBLIC ${Boost_LIBRARIES})

####################################################################################################################################################################################