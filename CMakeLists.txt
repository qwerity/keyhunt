cmake_minimum_required(VERSION 3.29)
project(cuda-keyhunt-pvk CXX CUDA)

####################################################################################################################################################################################
include(CMakeGraphVizOptions)
set(CMAKE_GRAPHVIZ_OUTPUT "${CMAKE_BINARY_DIR}/graphviz")
set(CMAKE_GRAPHVIZ_GENERATE_TARGETS ON)
set(CMAKE_GRAPHVIZ_GENERATE_DEPENDENCIES ON)

include(FetchContent)
include(cmake/utils.cmake)

####################################################################################################################################################################################
FetchContent_Declare(
    nlohmann_json
    URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
)
FetchContent_MakeAvailable(nlohmann_json)

include_directories(SYSTEM ${nlohmann_json_SOURCE_DIR}/include)

####################################################################################################################################################################################
# Set the C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

####################################################################################################################################################################################
#set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded")

####################################################################################################################################################################################
option(BUILD_TESTS "Build test_bitcoin executable." OFF)

####################################################################################################################################################################################
if(WIN32)
    set(OPENSSL_ROOT_DIR "${CMAKE_SOURCE_DIR}/external/openssl")
endif()
set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL 3 REQUIRED)
include_directories(SYSTEM ${OPENSSL_INCLUDE_DIR})

####################################################################################################################################################################################
find_package(CUDAToolkit 12 EXACT REQUIRED)
include_directories(SYSTEM ${CUDAToolkit_INCLUDE_DIRS})

####################################################################################################################################################################################
if(WIN32)
    set(BOOST_ROOT "C:/boost/boost-1.86.0/")
    set(BOOST_LIBRARYDIR "${BOOST_ROOT}/stage/lib")

    set(Boost_USE_STATIC_LIBS ON)
    set(Boost_USE_STATIC_RUNTIME ON)
    set(Boost_USE_MULTITHREADED ON)
    set(Boost_NO_WARN_NEW_VERSIONS ON)

    # Set _WIN32_WINNT and BOOST_USE_WINAPI_VERSION to target Windows 8
    add_definitions(-D_WIN32_WINNT=0x0602 -DBOOST_USE_WINAPI_VERSION=0x0602)
endif()

find_package(Boost 1.80 REQUIRED COMPONENTS system log_setup log iostreams regex)
include_directories(SYSTEM ${Boost_INCLUDE_DIRS})

####################################################################################################################################################################################
# Set compiler options
# Set the C++ compiler flags for Debug and Release configurations
set(CMAKE_CXX_FLAGS_DEBUG "-Wall")
set(CMAKE_CXX_FLAGS_RELEASE "-DNDEBUG")
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "-Wall")

if(WIN32)
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /fsanitize=address")
    set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO} /fsanitize=address")
else()
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g")
    set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO} -g")
endif()
####################################################################################################################################################################################
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_SOURCE_DIR}/bin)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG ${CMAKE_SOURCE_DIR}/bin)

include_directories(${CMAKE_SOURCE_DIR})

####################################################################################################################################################################################
add_subdirectory(util)
add_subdirectory(cuda)
add_subdirectory(tools)

####################################################################################################################################################################################
set(MAIN_SRC
    main.cpp
    key_hunter.cpp
    key_hunter.h
    results_processor.cpp
    results_processor.h
)
add_executable(${PROJECT_NAME} ${MAIN_SRC})
suppress_target_msvc_warnings(${PROJECT_NAME})

target_link_libraries(${PROJECT_NAME} PRIVATE util)
target_link_libraries(${PROJECT_NAME} PRIVATE cuda_keys)

# TESTS ############################################################################################################################################################################
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

####################################################################################################################################################################################
