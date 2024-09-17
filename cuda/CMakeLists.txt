project(cuda_keys CUDA)

set(CMAKE_CUDA_STANDARD 20)
set(CMAKE_CUDA_STANDARD_REQUIRED ON)

set(THRUST_CPP_DIALECT 20)

####################################################################################################################################################################################
include_directories(${CMAKE_SOURCE_DIR}/util)

####################################################################################################################################################################################
if (NOT DEFINED CMAKE_CUDA_ARCHITECTURES)
    set(CMAKE_CUDA_ARCHITECTURES "52;61;70;86") # lowest CUDA 12 standard + lowest for integer intrinsics
endif()
message(STATUS "Using CUDA architectures: ${CMAKE_CUDA_ARCHITECTURES}")

####################################################################################################################################################################################
# Set the CUDA compiler flags for Debug and Release configurations
set(CUDA_PROFILING_OUTPUT "--ptxas-options=-v")
#set(CUDA_SUPPRESS_WARNINGS "-diag-suppress 20091")
set(NVCC_COMPILATION_FLAGS "--split-compile=0 --threads=0")
set(CMAKE_CUDA_FLAGS "-rdc=true --default-stream per-thread ${CUDA_PROFILING_OUTPUT} ${CUDA_SUPPRESS_WARNINGS} ${NVCC_COMPILATION_FLAGS}")
set(CMAKE_CUDA_FLAGS_DEBUG "-O0 -g -lineinfo") # -G enables device-side debugging but significantly slows down the compilation
set(CMAKE_CUDA_FLAGS_RELEASE "-O3 --use_fast_math -DNDEBUG")
set(CMAKE_CUDA_FLAGS_RELWITHDEBINFO "-O2 -g -lineinfo")

####################################################################################################################################################################################
set(SRC
    ecc.cu
    ecc.cuh
    ecc_helper.cu
    ecc_helper.cuh

    secp256k1.cuh

    udevice_vector.cuh

    ptx.cuh
    functors.cuh
    defines.cuh

    sha256.cuh
    ripemd160.cuh

    hash160_lookup.cu
    hash160_lookup.cuh

    atomic_list.cuh
    atomic_list.cu
)

set_source_files_properties(hash160_lookup.cu PROPERTIES COMPILE_FLAGS $<$<CONFIG:Debug>:-G>)
set_source_files_properties(ecc.cu PROPERTIES COMPILE_FLAGS $<$<CONFIG:Debug>:-G>)
set_source_files_properties(secp256k1.cuh PROPERTIES COMPILE_FLAGS $<$<CONFIG:Debug>:-G>)
set_source_files_properties(hash160_lookup.cu PROPERTIES COMPILE_FLAGS $<$<CONFIG:Debug>:-G>)

add_library(cuda_keys ${SRC})
set_target_properties(cuda_keys PROPERTIES
    CUDA_RESOLVE_DEVICE_SYMBOLS ON
    CUDA_SEPARABLE_COMPILATION ON
    POSITION_INDEPENDENT_CODE ON
)
target_compile_options(cuda_keys PRIVATE $<$<COMPILE_LANGUAGE:CUDA>:-Xcompiler=-Wall -Wextra>)

target_link_libraries(cuda_keys PRIVATE util)
target_link_libraries(cuda_keys PRIVATE CUDA::cudart)

####################################################################################################################################################################################
