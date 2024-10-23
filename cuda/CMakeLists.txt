####################################################################################################################################################################################
set(CMAKE_CUDA_STANDARD_REQUIRED ON)

if (MSVC)
    if (MSVC_VERSION GREATER_EQUAL 1930)  # Visual Studio 2022
        set(CMAKE_CUDA_STANDARD 20)
    elseif (MSVC_VERSION GREATER_EQUAL 1920 AND MSVC_VERSION LESS 1930)  # Visual Studio 2019
        set(CMAKE_CUDA_STANDARD 17)
    else()
        # Unknown or unsupported MSVC version. Using CUDA 17 by default.
        set(CMAKE_CUDA_STANDARD 17)
    endif()
else()
    set(CMAKE_CUDA_STANDARD 20)
endif()

####################################################################################################################################################################################
if (NOT DEFINED CMAKE_CUDA_ARCHITECTURES)
    set(CMAKE_CUDA_ARCHITECTURES all)
endif()
message(STATUS "Using CUDA architectures: ${CMAKE_CUDA_ARCHITECTURES}")

####################################################################################################################################################################################
# Set the CUDA compiler flags for Debug and Release configurations
set(CUDA_PROFILING_OUTPUT "--ptxas-options=-v")
#set(CUDA_SUPPRESS_WARNINGS "-diag-suppress 20091")
#set(CUDA_SUPPRESS_WARNINGS "-diag-suppress 20012")
#set(NVCC_COMPILATION_FLAGS "--split-compile=0 --threads=0")

set(CMAKE_CUDA_FLAGS "-rdc=true --expt-relaxed-constexpr --default-stream per-thread ${CUDA_PROFILING_OUTPUT} ${CUDA_SUPPRESS_WARNINGS} ${NVCC_COMPILATION_FLAGS}")
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
#set_source_files_properties(ecc_helper.cu PROPERTIES COMPILE_FLAGS $<$<CONFIG:Debug>:-G>)
set_source_files_properties(secp256k1.cuh PROPERTIES COMPILE_FLAGS $<$<CONFIG:Debug>:-G>)
set_source_files_properties(hash160_lookup.cu PROPERTIES COMPILE_FLAGS $<$<CONFIG:Debug>:-G>)
set_source_files_properties(atomic_list.cu PROPERTIES COMPILE_FLAGS $<$<CONFIG:Debug>:-G>)

add_library(cuda_keys STATIC ${SRC})
set_target_properties(cuda_keys PROPERTIES
    CUDA_RESOLVE_DEVICE_SYMBOLS ON
    CUDA_SEPARABLE_COMPILATION ON
    POSITION_INDEPENDENT_CODE ON
)

target_link_libraries(cuda_keys PRIVATE CUDA::cudart_static)

####################################################################################################################################################################################
