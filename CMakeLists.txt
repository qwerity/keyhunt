cmake_minimum_required(VERSION 3.29)
project(cuda-keyhunt-pvk CXX CUDA)

####################################################################################################################################################################################
include(FetchContent)

####################################################################################################################################################################################
FetchContent_Declare(
    json
    URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
)
FetchContent_MakeAvailable(json)

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
find_package(OpenSSL 3 REQUIRED)

####################################################################################################################################################################################
find_package(CUDAToolkit 12 EXACT REQUIRED)
include_directories(SYSTEM ${CUDAToolkit_INCLUDE_DIRS})

####################################################################################################################################################################################
if(WIN32)
    set(BOOST_ROOT "C:/boost/boost-1.86.0/")
    set(BOOST_LIBRARYDIR "${BOOST_ROOT}/stage/lib")

    set(Boost_USE_STATIC_LIBS ON)
    set(Boost_NO_WARN_NEW_VERSIONS ON)

    # Set _WIN32_WINNT and BOOST_USE_WINAPI_VERSION to target Windows 8
    add_definitions(-D_WIN32_WINNT=0x0602 -DBOOST_USE_WINAPI_VERSION=0x0602)
endif()

find_package(Boost 1.80 REQUIRED COMPONENTS system log_setup log iostreams regex)
include_directories(SYSTEM ${Boost_INCLUDE_DIRS})

####################################################################################################################################################################################
# Set compiler options
# Set the C++ compiler flags for Debug and Release configurations
set(CMAKE_CXX_FLAGS_DEBUG "-g -Wall")
set(CMAKE_CXX_FLAGS_RELEASE "-DNDEBUG")
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "-g -Wall")

if(WIN32)
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /fsanitize=address")
    set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO} /fsanitize=address")
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
target_link_libraries(${PROJECT_NAME} PRIVATE util)
target_link_libraries(${PROJECT_NAME} PRIVATE nlohmann_json::nlohmann_json)
target_link_libraries(${PROJECT_NAME} PRIVATE cuda_keys)
target_link_libraries(${PROJECT_NAME} PRIVATE ${Boost_LIBRARIES})

# TESTS ############################################################################################################################################################################
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

####################################################################################################################################################################################
