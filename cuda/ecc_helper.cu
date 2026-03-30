#include "ecc_helper.cuh"
#include "common_kernels.cuh"
#include "ec_4limb_math.cuh"

#include "secp256k1_v2/bip32.cuh"
#include "secp256k1_v2/secp256k1.cuh"
#include "secp256k1_v2/secp256k1_defines.cuh"

extern __constant__ uint32_t d_pointsPerThread;
extern __constant__ uint32_t d_seedPairsPerThread;

extern __constant__ uint256_t *d_publicKeyXPtr;
extern __constant__ uint256_t *d_publicKeyYPtr;

__constant__ int d_publicKeyCompressionTypeToCheck{PointCompressionType::BOTH};

// 4-limb GTable: each point = 4 uint64_t (X) + 4 uint64_t (Y). Index = (chunk*65536 + (val-1)) * 4 for uint64_t offset.
__constant__ const uint64_t* d_gTableX_4limb_ptr = nullptr;
__constant__ const uint64_t* d_gTableY_4limb_ptr = nullptr;

// secp256k1 group order N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
__constant__ uint256_t secp256k1_N;

__device__ __forceinline__ bool uint256_greater_or_equal(const uint256_t& a, const uint256_t& b)
{
    for (int i = 7; i >= 0; --i)
    {
        if (a.v[i] > b.v[i])
            return true;
        if (a.v[i] < b.v[i])
            return false;
    }
    return true; // equal
}

__device__ __forceinline__ void uint256_sub(uint256_t& result, const uint256_t& a, const uint256_t& b)
{
    uint64_t borrow = 0;
#pragma unroll
    for (int i = 0; i < 8; ++i)
    {
        uint64_t diff = static_cast<uint64_t>(a.v[i]) - static_cast<uint64_t>(b.v[i]) - borrow;
        result.v[i] = static_cast<uint32_t>(diff);
        borrow = (diff > 0xFFFFFFFFULL) ? 1 : 0;
    }
}

__device__ __forceinline__ void reduce_mod_N(const uint256_t& x, uint256_t& result)
{
// Copy x to result
#pragma unroll
    for (int i = 0; i < 8; ++i)
    {
        result.v[i] = x.v[i];
    }

    // Reduce modulo N (group order)
    // If result >= N, subtract N (at most once, since x is already in field)
    if (uint256_greater_or_equal(result, secp256k1_N))
    {
        uint256_t temp;
        uint256_sub(temp, result, secp256k1_N);
#pragma unroll
        for (int i = 0; i < 8; ++i)
        {
            result.v[i] = temp.v[i];
        }
    }
}

__global__ void checkHashKernel(const uint256_t *privateKeys)
{
    const uint32_t totalThreads = gridDim.x * blockDim.x;
    const uint32_t threadId = blockDim.x * blockIdx.x + threadIdx.x;

    uint256_t privateKey;
    uint256_t publicX;
    uint256_t publicY;

#pragma unroll
    for(uint32_t i = 0; i < d_pointsPerThread; ++i)
    {
        const uint32_t base = i * totalThreads;
        const uint32_t index = base + threadId;

        // Read data for current iteration
        readUInt256(privateKeys, i, privateKey);
        readUInt256(d_publicKeyXPtr, i, publicX);

        // TODO: make in future mode for config
        if (1) {
            uint256_t publicR;

            // Reduce x-coordinate modulo N (group order)
            reduce_mod_N(publicX, publicR);

            // Take first 5 words from publicR
            uint32_t publicRFirst5[5];
#pragma unroll
            for (int j = 0; j < 5; ++j)
            {
                publicRFirst5[j] = publicR.v[j];
            }

            // Check if first 5 words from publicR match target
            if (checkHash(publicRFirst5))
            {
                setResultFound(index, true, privateKey, publicRFirst5);
            }
        }

        // Optimize: read Y coordinate only if needed
        const bool needCompressed = (d_publicKeyCompressionTypeToCheck == PointCompressionType::COMPRESSED || d_publicKeyCompressionTypeToCheck == PointCompressionType::BOTH);
        const bool needUncompressed = (d_publicKeyCompressionTypeToCheck == PointCompressionType::UNCOMPRESSED || d_publicKeyCompressionTypeToCheck == PointCompressionType::BOTH);

        if (needCompressed)
        {
            hash160 hash160;
            uint256_t sha256Digest;
            sha256PublicKeyCompressed(publicX, readUInt256LSW(d_publicKeyYPtr, i), sha256Digest);
            uint32_t swapped[8];
#pragma unroll
            for (int j = 0; j < 8; ++j)
            {
                uint32_t x = sha256Digest.v[j];
                swapped[j] = (x << 24) | ((x << 8) & 0x00ff0000) | ((x >> 8) & 0x0000ff00) | (x >> 24);
            }
            ripemd160sha256(swapped, hash160.h);

            if (checkHash(hash160))
            {
                setResultFound(index, true, privateKey, hash160.h);
            }
        }

        if (needUncompressed)
        {
            readUInt256(d_publicKeyYPtr, i, publicY);

            hash160 hash160;
            uint256_t sha256Digest;
            sha256PublicKey(publicX, publicY, sha256Digest);
            uint32_t swapped[8];
#pragma unroll
            for (int j = 0; j < 8; ++j)
            {
                uint32_t x = sha256Digest.v[j];
                swapped[j] = (x << 24) | ((x << 8) & 0x00ff0000) | ((x >> 8) & 0x0000ff00) | (x >> 24);
            }
            ripemd160sha256(swapped, hash160.h);

            if (checkHash(hash160))
            {
                setResultFound(index, false, privateKey, hash160.h);
            }
        }
    }
}

__device__ __forceinline__ void uint256_to_secp256k1_bytes_optimized(const uint256_t& src, uint8_t* dst)
{
    const uint32_t* v = src.v;
    const uint32_t w7 = v[7];
    dst[0] = static_cast<uint8_t>(w7 >> 24);
    dst[1] = static_cast<uint8_t>(w7 >> 16);
    dst[2] = static_cast<uint8_t>(w7 >> 8);
    dst[3] = static_cast<uint8_t>(w7);

    // v[6] -> dst[4..7]
    const uint32_t w6 = v[6];
    dst[4] = static_cast<uint8_t>(w6 >> 24);
    dst[5] = static_cast<uint8_t>(w6 >> 16);
    dst[6] = static_cast<uint8_t>(w6 >> 8);
    dst[7] = static_cast<uint8_t>(w6);

    // v[5] -> dst[8..11]
    const uint32_t w5 = v[5];
    dst[8] = static_cast<uint8_t>(w5 >> 24);
    dst[9] = static_cast<uint8_t>(w5 >> 16);
    dst[10] = static_cast<uint8_t>(w5 >> 8);
    dst[11] = static_cast<uint8_t>(w5);

    // v[4] -> dst[12..15]
    const uint32_t w4 = v[4];
    dst[12] = static_cast<uint8_t>(w4 >> 24);
    dst[13] = static_cast<uint8_t>(w4 >> 16);
    dst[14] = static_cast<uint8_t>(w4 >> 8);
    dst[15] = static_cast<uint8_t>(w4);

    // v[3] -> dst[16..19]
    const uint32_t w3 = v[3];
    dst[16] = static_cast<uint8_t>(w3 >> 24);
    dst[17] = static_cast<uint8_t>(w3 >> 16);
    dst[18] = static_cast<uint8_t>(w3 >> 8);
    dst[19] = static_cast<uint8_t>(w3);

    // v[2] -> dst[20..23]
    const uint32_t w2 = v[2];
    dst[20] = static_cast<uint8_t>(w2 >> 24);
    dst[21] = static_cast<uint8_t>(w2 >> 16);
    dst[22] = static_cast<uint8_t>(w2 >> 8);
    dst[23] = static_cast<uint8_t>(w2);

    // v[1] -> dst[24..27]
    const uint32_t w1 = v[1];
    dst[24] = static_cast<uint8_t>(w1 >> 24);
    dst[25] = static_cast<uint8_t>(w1 >> 16);
    dst[26] = static_cast<uint8_t>(w1 >> 8);
    dst[27] = static_cast<uint8_t>(w1);

    const uint32_t w0 = v[0];
    dst[28] = static_cast<uint8_t>(w0 >> 24);
    dst[29] = static_cast<uint8_t>(w0 >> 16);
    dst[30] = static_cast<uint8_t>(w0 >> 8);
    dst[31] = static_cast<uint8_t>(w0);
}

__device__ __forceinline__ void secp256k1_bytes_to_uint256_optimized(const uint8_t* src, uint256_t& dst)
{
    // Оптимизация: используем прямое чтение с правильным порядком байт
    // Это быстрее, чем побайтовое чтение
    uint32_t* v = dst.v;

    // Читаем 32 байта как 8 uint32_t в big-endian формате
    // src[0-3] -> v[7] (big-endian)
    v[7] = (static_cast<uint32_t>(src[0]) << 24) |
           (static_cast<uint32_t>(src[1]) << 16) |
           (static_cast<uint32_t>(src[2]) << 8) |
           (static_cast<uint32_t>(src[3]));

    // src[4..7] -> v[6]
    v[6] = (static_cast<uint32_t>(src[4]) << 24) |
           (static_cast<uint32_t>(src[5]) << 16) |
           (static_cast<uint32_t>(src[6]) << 8) |
           (static_cast<uint32_t>(src[7]));

    // src[8..11] -> v[5]
    v[5] = (static_cast<uint32_t>(src[8]) << 24) |
           (static_cast<uint32_t>(src[9]) << 16) |
           (static_cast<uint32_t>(src[10]) << 8) |
           (static_cast<uint32_t>(src[11]));

    // src[12..15] -> v[4]
    v[4] = (static_cast<uint32_t>(src[12]) << 24) |
           (static_cast<uint32_t>(src[13]) << 16) |
           (static_cast<uint32_t>(src[14]) << 8) |
           (static_cast<uint32_t>(src[15]));

    // src[16..19] -> v[3]
    v[3] = (static_cast<uint32_t>(src[16]) << 24) |
           (static_cast<uint32_t>(src[17]) << 16) |
           (static_cast<uint32_t>(src[18]) << 8) |
           (static_cast<uint32_t>(src[19]));

    // src[20..23] -> v[2]
    v[2] = (static_cast<uint32_t>(src[20]) << 24) |
           (static_cast<uint32_t>(src[21]) << 16) |
           (static_cast<uint32_t>(src[22]) << 8) |
           (static_cast<uint32_t>(src[23]));

    // src[24..27] -> v[1]
    v[1] = (static_cast<uint32_t>(src[24]) << 24) |
           (static_cast<uint32_t>(src[25]) << 16) |
           (static_cast<uint32_t>(src[26]) << 8) |
           (static_cast<uint32_t>(src[27]));

    v[0] = (static_cast<uint32_t>(src[28]) << 24) |
           (static_cast<uint32_t>(src[29]) << 16) |
           (static_cast<uint32_t>(src[30]) << 8) |
           (static_cast<uint32_t>(src[31]));
}

// ---------------------------------------------------------------------------------
// 4-limb path: extract 16-bit chunks from uint256_t (same layout as secp256k1 scalar)
// ---------------------------------------------------------------------------------
__device__ __forceinline__ void uint256_to_16bit_chunks(const uint256_t& key, uint16_t chunks[16])
{
#pragma unroll
    for (int c = 0; c < 16; c++) {
        int w = c / 2;
        int shift = (c & 1) ? 16 : 0;
        chunks[c] = static_cast<uint16_t>((key.v[w] >> shift) & 0xFFFFu);
    }
}

// Convert 4-limb (uint64_t[4], little-endian limbs) to uint256_t (v[0]=LSW)
__device__ __forceinline__ void ec4limb_to_uint256(const uint64_t limb[4], uint256_t& out)
{
    out.v[0] = static_cast<uint32_t>(limb[0]);
    out.v[1] = static_cast<uint32_t>(limb[0] >> 32);
    out.v[2] = static_cast<uint32_t>(limb[1]);
    out.v[3] = static_cast<uint32_t>(limb[1] >> 32);
    out.v[4] = static_cast<uint32_t>(limb[2]);
    out.v[5] = static_cast<uint32_t>(limb[2] >> 32);
    out.v[6] = static_cast<uint32_t>(limb[3]);
    out.v[7] = static_cast<uint32_t>(limb[3] >> 32);
}

// 4-limb point multiplication: GTable 16 chunks, mixed Jacobian-Affine.
// Warp divergence: "if (privChunks[chunk] > 0)" — different threads do 1..16 iterations.
__device__ __forceinline__ void ec4limb_PointMultiJacobianFast(
    uint64_t* qx, uint64_t* qy, uint64_t* qz,
    const uint16_t* privChunks,
    const uint64_t* gTableX, const uint64_t* gTableY)
{
    constexpr int NUM_CHUNK = 16;
    constexpr int CHUNK_SIZE = 65536;
    constexpr int LIMBS_PER_POINT = 4;

    qz[0] = 1; qz[1] = 0; qz[2] = 0; qz[3] = 0;
    int chunk = 0;

    for (; chunk < NUM_CHUNK; chunk++) {
        if (privChunks[chunk] > 0) {
            int idx = (chunk * CHUNK_SIZE + (privChunks[chunk] - 1)) * LIMBS_PER_POINT;
            qx[0] = __ldg(&gTableX[idx+0]); qx[1] = __ldg(&gTableX[idx+1]); qx[2] = __ldg(&gTableX[idx+2]); qx[3] = __ldg(&gTableX[idx+3]);
            qy[0] = __ldg(&gTableY[idx+0]); qy[1] = __ldg(&gTableY[idx+1]); qy[2] = __ldg(&gTableY[idx+2]); qy[3] = __ldg(&gTableY[idx+3]);
            chunk++;
            break;
        }
    }

    for (; chunk < NUM_CHUNK; chunk++) {
        if (privChunks[chunk] > 0) {
            uint64_t gx[4], gy[4];
            const int idx = (chunk * CHUNK_SIZE + (privChunks[chunk] - 1)) * LIMBS_PER_POINT;
            gx[0] = __ldg(&gTableX[idx+0]); gx[1] = __ldg(&gTableX[idx+1]); gx[2] = __ldg(&gTableX[idx+2]); gx[3] = __ldg(&gTableX[idx+3]);
            gy[0] = __ldg(&gTableY[idx+0]); gy[1] = __ldg(&gTableY[idx+1]); gy[2] = __ldg(&gTableY[idx+2]); gy[3] = __ldg(&gTableY[idx+3]);
            ec4limb_PointAddMixedAffine(qx, qy, qz, gx, gy);
        }
    }
}

/** Hash + check for one point; __noinline__ to reduce fused kernel register pressure and improve occupancy. */
__device__ __noinline__ void fusedHashAndCheck(const uint256_t& publicX, const uint256_t& publicY, const uint256_t& privateKey, uint32_t index)
{
    if (1)
    {
        uint256_t publicR;
        reduce_mod_N(publicX, publicR);
        uint32_t publicRFirst5[5];
#pragma unroll
        for (int j = 0; j < 5; ++j)
            publicRFirst5[j] = publicR.v[j];
        if (checkHash(publicRFirst5))
            setResultFound(index, true, privateKey, publicRFirst5);
    }

    const bool needCompressed = (d_publicKeyCompressionTypeToCheck == PointCompressionType::COMPRESSED || d_publicKeyCompressionTypeToCheck == PointCompressionType::BOTH);
    const bool needUncompressed = (d_publicKeyCompressionTypeToCheck == PointCompressionType::UNCOMPRESSED || d_publicKeyCompressionTypeToCheck == PointCompressionType::BOTH);

    if (needCompressed)
    {
        hash160 hash160;
        hashPublicKeyCompressed(publicX, publicY.v[0] & 1, hash160.h);
        if (checkHash(hash160))
            setResultFound(index, true, privateKey, hash160.h);
    }

    if (needUncompressed)
    {
        hash160 hash160;
        hashPublicKey(publicX, publicY, hash160.h);
        if (checkHash(hash160))
            setResultFound(index, false, privateKey, hash160.h);
    }
}

/**
 * Fused kernel (4-limb): public key via 4-limb GTable + hash + check in one pass.
 * (256,4)+batch4 даёт 66% occupancy, но скорость падает ~3x — больше итераций, меньше эффективность батча.
 * (256,3) fails: callees PointAddMixedAffine (126 regs) and ModMult (94 regs) exceed 85 reg/thread.
 * (256,2), batch 8 — 25% occupancy, 128 reg/thread limit.
 */
__global__ void __launch_bounds__(256, 2) publicKeyAndCheckHash160FusedKernel(const uint256_t* privateKeys)
{
    const uint32_t totalThreads = gridDim.x * blockDim.x;
    const uint32_t threadId = blockDim.x * blockIdx.x + threadIdx.x;
    constexpr uint32_t MAX_BATCH_SIZE = 8;
    const uint64_t* gTableX = d_gTableX_4limb_ptr;
    const uint64_t* gTableY = d_gTableY_4limb_ptr;

    for (uint32_t batchStart = 0; batchStart < d_pointsPerThread; batchStart += MAX_BATCH_SIZE)
    {
        // Prefetch next batch's key for this thread to hide global memory latency
        if (batchStart + MAX_BATCH_SIZE < d_pointsPerThread)
        {
            const uint32_t nextDepth = batchStart + MAX_BATCH_SIZE;
            const uint32_t nextIndex = nextDepth * totalThreads + threadId;
#if defined(__CUDA_ARCH__) && __CUDA_ARCH__ >= 700
            asm volatile("prefetch.global.L2 [%0];" : : "l"(&privateKeys[nextIndex]) : "memory");
#endif
        }

        const uint32_t batchSize = (MAX_BATCH_SIZE < (d_pointsPerThread - batchStart)) ? MAX_BATCH_SIZE : (d_pointsPerThread - batchStart);
        uint64_t batchQx[MAX_BATCH_SIZE][4];
        uint64_t batchQy[MAX_BATCH_SIZE][4];
        uint64_t batchQz[MAX_BATCH_SIZE][4];
        uint256_t batchPrivateKeys[MAX_BATCH_SIZE];
        uint16_t chunks[16];

        for (uint32_t i = 0; i < batchSize; ++i)
        {
            uint256_t privateKey;
            readUInt256(privateKeys, batchStart + i, privateKey);
            batchPrivateKeys[i] = privateKey;
            uint256_to_16bit_chunks(privateKey, chunks);
            ec4limb_PointMultiJacobianFast(batchQx[i], batchQy[i], batchQz[i], chunks, gTableX, gTableY);
        }

        ec4limb_BatchJacobianToAffine<8>(batchQx, batchQy, batchQz, static_cast<int>(batchSize));

        for (uint32_t i = 0; i < batchSize; ++i)
        {
            const uint32_t index = (batchStart + i) * totalThreads + threadId;
            uint256_t publicX, publicY;
            ec4limb_to_uint256(batchQx[i], publicX);
            ec4limb_to_uint256(batchQy[i], publicY);
            fusedHashAndCheck(publicX, publicY, batchPrivateKeys[i], index);
        }
    }
}

/**
 * Mode-2 fused kernel: privateKeys is laid out as
 *   [first key for each seed][second key for each seed]
 * with d_seedPairsPerThread entries in each half.
 * Process both keys for the same seed in one thread batch to share control flow
 * and batch affine normalization across the pair.
 */
__global__ void __launch_bounds__(256, 2) publicKeyAndCheckHash160FusedKernel2(const uint256_t* privateKeys)
{
    const uint32_t totalThreads = gridDim.x * blockDim.x;
    const uint32_t threadId = blockDim.x * blockIdx.x + threadIdx.x;
    constexpr uint32_t MAX_SEED_BATCH_SIZE = 8;
    constexpr uint32_t MAX_POINT_BATCH_SIZE = MAX_SEED_BATCH_SIZE * 2;
    const uint64_t* gTableX = d_gTableX_4limb_ptr;
    const uint64_t* gTableY = d_gTableY_4limb_ptr;
    const uint32_t secondKeyDepthBase = d_seedPairsPerThread;

    for (uint32_t batchStart = 0; batchStart < d_seedPairsPerThread; batchStart += MAX_SEED_BATCH_SIZE) {
        if (batchStart + MAX_SEED_BATCH_SIZE < d_seedPairsPerThread) {
            const uint32_t nextDepth = batchStart + MAX_SEED_BATCH_SIZE;
            const uint32_t nextIndex1 = nextDepth * totalThreads + threadId;
            const uint32_t nextIndex2 = (secondKeyDepthBase + nextDepth) * totalThreads + threadId;
#if defined(__CUDA_ARCH__) && __CUDA_ARCH__ >= 700
            asm volatile("prefetch.global.L2 [%0];" : : "l"(&privateKeys[nextIndex1]) : "memory");
            asm volatile("prefetch.global.L2 [%0];" : : "l"(&privateKeys[nextIndex2]) : "memory");
#endif
        }

        const uint32_t seedBatchSize = (MAX_SEED_BATCH_SIZE < (d_seedPairsPerThread - batchStart))
                                           ? MAX_SEED_BATCH_SIZE
                                           : (d_seedPairsPerThread - batchStart);
        const uint32_t pointBatchSize = seedBatchSize * 2;

        uint64_t batchQx[MAX_POINT_BATCH_SIZE][4];
        uint64_t batchQy[MAX_POINT_BATCH_SIZE][4];
        uint64_t batchQz[MAX_POINT_BATCH_SIZE][4];
        uint256_t batchPrivateKeys[MAX_POINT_BATCH_SIZE];
        uint32_t batchIndices[MAX_POINT_BATCH_SIZE];
        uint16_t chunks[16];

        for (uint32_t i = 0; i < seedBatchSize; ++i) {
            const uint32_t firstDepth = batchStart + i;
            const uint32_t secondDepth = secondKeyDepthBase + firstDepth;
            const uint32_t firstSlot = i * 2;
            const uint32_t secondSlot = firstSlot + 1;

            readUInt256(privateKeys, firstDepth, batchPrivateKeys[firstSlot]);
            batchIndices[firstSlot] = firstDepth * totalThreads + threadId;
            uint256_to_16bit_chunks(batchPrivateKeys[firstSlot], chunks);
            ec4limb_PointMultiJacobianFast(batchQx[firstSlot], batchQy[firstSlot], batchQz[firstSlot], chunks, gTableX,
                                           gTableY);

            readUInt256(privateKeys, secondDepth, batchPrivateKeys[secondSlot]);
            batchIndices[secondSlot] = secondDepth * totalThreads + threadId;
            uint256_to_16bit_chunks(batchPrivateKeys[secondSlot], chunks);
            ec4limb_PointMultiJacobianFast(batchQx[secondSlot], batchQy[secondSlot], batchQz[secondSlot], chunks,
                                           gTableX, gTableY);
        }

        ec4limb_BatchJacobianToAffine<MAX_POINT_BATCH_SIZE>(batchQx, batchQy, batchQz,
                                                            static_cast<int>(pointBatchSize));

        for (uint32_t i = 0; i < pointBatchSize; ++i) {
            uint256_t publicX, publicY;
            ec4limb_to_uint256(batchQx[i], publicX);
            ec4limb_to_uint256(batchQy[i], publicY);
            fusedHashAndCheck(publicX, publicY, batchPrivateKeys[i], batchIndices[i]);
        }
    }
}

__global__ void publicKeyGenerationKernel(const uint256_t *privateKeys)
{
    constexpr uint32_t MAX_BATCH_SIZE = 16;

    if (d_pointsPerThread <= MAX_BATCH_SIZE)
    {
        secp256k1_gej points[MAX_BATCH_SIZE];
        secp256k1_ge normalized_points[MAX_BATCH_SIZE];

        for(uint32_t i = 0; i < d_pointsPerThread; ++i)
        {
            HDExtendedPrivateKey privateExKey;
            uint256_t privateKey;
            readUInt256(privateKeys, i, privateKey);

            uint256_to_secp256k1_bytes_optimized(privateKey, privateExKey.key);
            secp256k1_ec_pubkey_create_gej(&points[i], &privateExKey.key[0]);
        }

        secp256k1_ge_set_gej_batch(normalized_points, points, d_pointsPerThread);

        for(uint32_t i = 0; i < d_pointsPerThread; ++i)
        {
            uint8_t pubkey[64];
            secp256k1_pubkey_save(pubkey, &normalized_points[i]);

            uint256_t newX, newY;
            secp256k1_bytes_to_uint256_optimized(pubkey, newX);
            secp256k1_bytes_to_uint256_optimized(pubkey + 32, newY);

            writeUInt256(newX, i, d_publicKeyXPtr);
            writeUInt256(newY, i, d_publicKeyYPtr);
        }
    }
    else
    {
        for(uint32_t batchStart = 0; batchStart < d_pointsPerThread; batchStart += MAX_BATCH_SIZE)
        {
            const uint32_t batchSize = (MAX_BATCH_SIZE < (d_pointsPerThread - batchStart)) ? MAX_BATCH_SIZE : (d_pointsPerThread - batchStart);
            secp256k1_gej points[MAX_BATCH_SIZE];
            secp256k1_ge normalized_points[MAX_BATCH_SIZE];

            for(uint32_t i = 0; i < batchSize; ++i)
            {
                HDExtendedPrivateKey privateExKey;
                uint256_t privateKey;
                readUInt256(privateKeys, batchStart + i, privateKey);

                uint256_to_secp256k1_bytes_optimized(privateKey, privateExKey.key);
                secp256k1_ec_pubkey_create_gej(&points[i], &privateExKey.key[0]);
            }

            secp256k1_ge_set_gej_batch(normalized_points, points, batchSize);

            for(uint32_t i = 0; i < batchSize; ++i)
            {
                uint8_t pubkey[64];
                secp256k1_pubkey_save(pubkey, &normalized_points[i]);

                uint256_t newX, newY;
                secp256k1_bytes_to_uint256_optimized(pubkey, newX);
                secp256k1_bytes_to_uint256_optimized(pubkey + 32, newY);

                writeUInt256(newX, batchStart + i, d_publicKeyXPtr);
                writeUInt256(newY, batchStart + i, d_publicKeyYPtr);
            }
        }
    }
}
