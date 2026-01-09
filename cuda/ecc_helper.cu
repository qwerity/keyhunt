#include "ecc_helper.cuh"
#include "common_kernels.cuh"

#include "secp256k1_v2/bip32.cuh"
#include "secp256k1_v2/secp256k1.cuh"

extern __constant__ uint32_t d_pointsPerThread;

extern __constant__ uint256_t *d_publicKeyXPtr;
extern __constant__ uint256_t *d_publicKeyYPtr;

__constant__ int d_publicKeyCompressionTypeToCheck{PointCompressionType::BOTH};

__global__ void checkHashKernel(const uint256_t *privateKeys)
{
    const uint32_t totalThreads = gridDim.x * blockDim.x;
    const uint32_t threadId = blockDim.x * blockIdx.x + threadIdx.x;

    uint256_t privateKey;
    uint256_t publicX;
    uint256_t publicY;
    hash160 hash160;

    #pragma unroll
    for(uint32_t i = 0; i < d_pointsPerThread; ++i)
    {
        readUInt256(privateKeys, i, privateKey);

        readUInt256(d_publicKeyXPtr, i, publicX);

        const uint32_t base = i * totalThreads;
        const uint32_t index = base + threadId;

        if (d_publicKeyCompressionTypeToCheck == PointCompressionType::COMPRESSED || d_publicKeyCompressionTypeToCheck == PointCompressionType::BOTH)
        {
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

        if (d_publicKeyCompressionTypeToCheck == PointCompressionType::UNCOMPRESSED || d_publicKeyCompressionTypeToCheck == PointCompressionType::BOTH)
        {
            readUInt256(d_publicKeyYPtr, i, publicY);

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
    uint32_t* v = dst.v;
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
