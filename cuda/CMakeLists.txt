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
set(CUDA_PROFILING_OUTPUT "--ptxas-options=-v --resource-usage")
#set(CUDA_SUPPRESS_WARNINGS "-diag-suppress 20091")
#set(CUDA_SUPPRESS_WARNINGS "-diag-suppress 20012")
#set(NVCC_COMPILATION_FLAGS "--split-compile=0 --threads=0")

set(CMAKE_CUDA_FLAGS "${CMAKE_CUDA_FLAGS} --expt-relaxed-constexpr -Xptxas -dlcm=ca ${CUDA_PROFILING_OUTPUT} ${CUDA_SUPPRESS_WARNINGS} ${NVCC_COMPILATION_FLAGS}")
set(CMAKE_CUDA_FLAGS_DEBUG "${CMAKE_CUDA_FLAGS_DEBUG} -O0 -G") # -G enables device-side debugging but significantly slows down the compilation

#message("CMAKE_CUDA_FLAGS: ${CMAKE_CUDA_FLAGS}")
#message("CMAKE_CUDA_FLAGS_DEBUG: ${CMAKE_CUDA_FLAGS_DEBUG}")
#message("CMAKE_CUDA_FLAGS_RELEASE: ${CMAKE_CUDA_FLAGS_RELEASE}")

####################################################################################################################################################################################
set(SECP256K1_V2_SRC
    secp256k1_v2/sha.cu
    secp256k1_v2/hmac.cu
    secp256k1_v2/bip32.cu
    secp256k1_v2/bip39.cu
    secp256k1_v2/secp256k1.cu
    secp256k1_v2/ripemd160.cu
)

####################################################################################################################################################################################
set(ECC_SRC
    ecc.cu
    ecc.cuh
    ecc_helper.cu
    ecc_helper.cuh
    ec_4limb_math.cuh
    gpu_hash160.cuh

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

    hd_wallet.cu
    hd_wallet.cuh
)

# SHARED so nvcc does full device link when building .so; fixes undefined __fatbinwrap_* / __cudaRegisterLinkedBinary_* when Rust links with lld
add_library(ecc_cuda SHARED ${ECC_SRC} ${SECP256K1_V2_SRC})
target_include_directories(ecc_cuda PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(ecc_cuda PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/secp256k1_v2)

set_target_properties(ecc_cuda PROPERTIES
    CUDA_RESOLVE_DEVICE_SYMBOLS ON
    CUDA_SEPARABLE_COMPILATION ON
)

target_link_libraries(ecc_cuda PRIVATE CUDA::cudart_static)

####################################################################################################################################################################################
# C API for Rust (or other host) — C++ wrapper around ecc_cuda
add_library(keyhunt_cuda_capi STATIC keyhunt_capi.cpp keyhunt_capi.h)
target_include_directories(keyhunt_cuda_capi PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(keyhunt_cuda_capi PUBLIC ${CMAKE_SOURCE_DIR})
target_link_libraries(keyhunt_cuda_capi PUBLIC ecc_cuda)

####################################################################################################################################################################################
