/*
 * GPUSecp_Phase2.h - Phase 2 Optimized secp256k1 GPU Header
 * 
 * Phase 2 Optimizations:
 * 1. Kernel Fusion (minimize global memory traffic)
 * 2. Inline functions for hot paths
 * 3. Optimized loop unrolling
 * 
 * Combined with Phase 1:
 * - Mixed Jacobian-Affine (8M+3S)
 * - Batch ModInv (Montgomery's trick)
 * 
 * Expected total speedup: ~2.5-2.8x vs original
 */

#ifndef GPUSECP_PHASE2_H
#define GPUSECP_PHASE2_H

#include <vector>
#include <stdint.h>
#include <stdio.h>
#include <cuda.h>
#include <cuda_runtime.h>
#include <curand.h>
#include <curand_kernel.h>

// ---------------------------------------------------------------------------------
// File/Folder Configuration
// ---------------------------------------------------------------------------------
#define NAME_HASH_FOLDER "TestHash"
#define NAME_SEED_FOLDER "TestBook"
#define NAME_HASH_BUFFER "merged-sorted-unique-8-byte-hashes"
#define NAME_INPUT_PRIME NAME_SEED_FOLDER "/list_prime"
#define NAME_INPUT_AFFIX NAME_SEED_FOLDER "/list_affix"
#define NAME_FILE_OUTPUT "TEST_OUTPUT"

// ---------------------------------------------------------------------------------
// CUDA Configuration
// ---------------------------------------------------------------------------------
#define BLOCKS_PER_GRID 30
#define THREADS_PER_BLOCK 256

// ---------------------------------------------------------------------------------
// PHASE 2: Batch size for optimal performance
// ---------------------------------------------------------------------------------
#define BATCH_SIZE 64

// ---------------------------------------------------------------------------------
// Input Configuration
// ---------------------------------------------------------------------------------
#define MAX_LEN_WORD_PRIME 20
#define MAX_LEN_WORD_AFFIX 4
#define AFFIX_IS_SUFFIX true
#define COUNT_INPUT_HASH 204
#define COUNT_INPUT_PRIME 100
#define COUNT_COMBO_SYMBOLS 100
#define SIZE_COMBO_MULTI 4

// ---------------------------------------------------------------------------------
// Memory Configuration  
// ---------------------------------------------------------------------------------
#define SIZE_CPU_STACK (1024 * 1024 * 1024)
#define SIZE_CUDA_STACK 32768

// ---------------------------------------------------------------------------------
// Fixed Constants (do not modify)
// ---------------------------------------------------------------------------------
#define SIZE_LONG 8
#define SIZE_HASH160 20
#define SIZE_PRIV_KEY 32
#define NUM_GTABLE_CHUNK 16
#define NUM_GTABLE_VALUE 65536
#define SIZE_GTABLE_POINT 32
#define IDX_CUDA_THREAD ((blockIdx.x * blockDim.x) + threadIdx.x)
#define COUNT_GTABLE_POINTS (NUM_GTABLE_CHUNK * NUM_GTABLE_VALUE)
#define COUNT_CUDA_THREADS (BLOCKS_PER_GRID * THREADS_PER_BLOCK)

// ---------------------------------------------------------------------------------
// Precomputed Constants
// ---------------------------------------------------------------------------------

// First element index for each GTable chunk
__constant__ int CHUNK_FIRST_ELEMENT[NUM_GTABLE_CHUNK] = {
    65536*0,  65536*1,  65536*2,  65536*3,
    65536*4,  65536*5,  65536*6,  65536*7,
    65536*8,  65536*9,  65536*10, 65536*11,
    65536*12, 65536*13, 65536*14, 65536*15,
};

// Index * 8 lookup table
__device__ __constant__ int MULTI_EIGHT[65] = { 0,
    0 + 8,   0 + 16,   0 + 24,   0 + 32,   0 + 40,   0 + 48,   0 + 56,   0 + 64,
   64 + 8,  64 + 16,  64 + 24,  64 + 32,  64 + 40,  64 + 48,  64 + 56,  64 + 64,
  128 + 8, 128 + 16, 128 + 24, 128 + 32, 128 + 40, 128 + 48, 128 + 56, 128 + 64,
  192 + 8, 192 + 16, 192 + 24, 192 + 32, 192 + 40, 192 + 48, 192 + 56, 192 + 64,
  256 + 8, 256 + 16, 256 + 24, 256 + 32, 256 + 40, 256 + 48, 256 + 56, 256 + 64,
  320 + 8, 320 + 16, 320 + 24, 320 + 32, 320 + 40, 320 + 48, 320 + 56, 320 + 64,
  384 + 8, 384 + 16, 384 + 24, 384 + 32, 384 + 40, 384 + 48, 384 + 56, 384 + 64,
  448 + 8, 448 + 16, 448 + 24, 448 + 32, 448 + 40, 448 + 48, 448 + 56, 448 + 64,
};

// Combo symbols (ASCII keyboard + special chars)
__device__ __constant__ uint8_t COMBO_SYMBOLS[COUNT_COMBO_SYMBOLS] = {
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
    0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60, 0x7B, 0x7C, 0x7D, 0x7E,
    0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A,
    0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A,
    0x00, 0x7F, 0xFF, 0x09, 0x0D
};

// ---------------------------------------------------------------------------------
// CUDA Error Handling
// ---------------------------------------------------------------------------------
#define CudaSafeCall(err) __cudaSafeCall(err, __FILE__, __LINE__)

// ---------------------------------------------------------------------------------
// GPUSecp Class - Phase 2
// ---------------------------------------------------------------------------------
class GPUSecp
{
public:
    GPUSecp(
        int primeCount, 
        int affixCount,
        const uint8_t *gTableXCPU,
        const uint8_t *gTableYCPU,
        const uint8_t *inputBookPrimeCPU, 
        const uint8_t *inputBookAffixCPU, 
        const uint64_t *inputHashBufferCPU
    );

    void doIterationSecp256k1Books(int iteration);
    void doIterationSecp256k1Combo(int8_t *inputComboCPU);
    void doPrintOutput();
    void doFreeMemory();

private:
    int8_t *inputComboGPU;
    uint8_t *gTableXGPU;
    uint8_t *gTableYGPU;
    uint8_t *inputBookPrimeGPU;
    uint8_t *inputBookAffixGPU;
    uint64_t *inputHashBufferGPU;
    uint8_t *outputBufferGPU;
    uint8_t *outputBufferCPU;
    uint8_t *outputHashesGPU;
    uint8_t *outputHashesCPU;
    uint8_t *outputPrivKeysGPU;
    uint8_t *outputPrivKeysCPU;
};

#endif // GPUSECP_PHASE2_H
