cmake_minimum_required(VERSION 3.10)
project(cuda_keys CUDA)

set(CMAKE_CUDA_STANDARD 20)
set(CMAKE_CUDA_STANDARD_REQUIRED ON)

set(THRUST_CPP_DIALECT 20)

# Set the CUDA compiler flags for Debug and Release configurations
set(CMAKE_CUDA_FLAGS "--extended-lambda -rdc=true --default-stream per-thread --expt-relaxed-constexpr")
set(CMAKE_CUDA_FLAGS_DEBUG "-g -G -O0")
set(CMAKE_CUDA_FLAGS_RELEASE "-O3 --use_fast_math -DNDEBUG")
set(CMAKE_CUDA_FLAGS_RELWITHDEBINFO "-O2 -g -G")

####################################################################################################################################################################################
include_directories(${CMAKE_SOURCE_DIR}/util)

####################################################################################################################################################################################
# CUDA setup
find_package(CUDAToolkit REQUIRED)
find_package(Thrust 2 REQUIRED CONFIG)
thrust_create_target(Thrust)

if (NOT DEFINED CMAKE_CUDA_ARCHITECTURES)
    set(CMAKE_CUDA_ARCHITECTURES "52;61;70;86") # lowest CUDA 12 standard + lowest for integer intrinsics
endif()
message(STATUS "Using CUDA architectures: ${CMAKE_CUDA_ARCHITECTURES}")

# Apply the compiler flags based on the build type
if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CMAKE_CUDA_FLAGS "${CMAKE_CUDA_FLAGS} ${CMAKE_CUDA_FLAGS_DEBUG} -Xcompiler=${CMAKE_CXX_FLAGS_DEBUG}")
elseif (CMAKE_BUILD_TYPE STREQUAL "Release")
    set(CMAKE_CUDA_FLAGS "${CMAKE_CUDA_FLAGS} ${CMAKE_CUDA_FLAGS_RELEASE} -Xcompiler=${CMAKE_CXX_FLAGS_RELEASE}")
elseif (CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
    set(CMAKE_CUDA_FLAGS "${CMAKE_CUDA_FLAGS} ${CMAKE_CUDA_FLAGS_RELWITHDEBINFO} -Xcompiler=${CMAKE_CXX_FLAGS_RELWITHDEBINFO}")
endif()

####################################################################################################################################################################################
set(SRC
    ecc.cu
    ecc.cuh

    secp256k1.cuh

    udevice_vector.cuh

    ptx.cuh
    functors.cuh
    defines.cuh

    sha256.cuh
    ripemd160.cuh
)

add_library(cuda_keys ${SRC})
set_target_properties(cuda_keys PROPERTIES
    CUDA_RESOLVE_DEVICE_SYMBOLS ON
    CUDA_SEPARABLE_COMPILATION ON
    POSITION_INDEPENDENT_CODE ON
)
target_link_libraries(cuda_keys PRIVATE util)
target_link_libraries(cuda_keys PRIVATE CUDA::cudart_static)
target_link_libraries(cuda_keys PRIVATE Thrust)
target_compile_options(cuda_keys PRIVATE $<$<COMPILE_LANGUAGE:CUDA>:-Xcompiler=-Wall -Wextra>)

