#include "ecc_helper.cuh"
#include "common_kernels.cuh"

#include "secp256k1_v2/bip32.cuh"

extern __constant__ uint32_t d_pointsPerThread;

extern __constant__ uint256_t *d_publicKeyXPtr;
extern __constant__ uint256_t *d_publicKeyYPtr;

// Check public key hash160 compressed/uncompressed/both
__constant__ int d_publicKeyCompressionTypeToCheck{PointCompressionType::BOTH};

__device__ void print(uint256_t& x, uint32_t step, uint32_t idx, char op)
{
    if (idx != 0)
        return;

    printf("op: %c step: %u, idx: %u, x: ", op, step, idx);
    for (size_t i = 0; i < 8; ++i)
    {
        // Print the 4 bytes of each uint32_t directly
        printf("%02x %02x %02x %02x ",
               (x[i] & 0x000000FF),        // Least significant byte
               (x[i] & 0x0000FF00) >> 8,   // Second byte
               (x[i] & 0x00FF0000) >> 16,  // Third byte
               (x[i] & 0xFF000000) >> 24   // Most significant byte
        );
    }
    printf("\n");
}

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
            hashPublicKeyCompressed(publicX, readUInt256LSW(d_publicKeyYPtr, i), hash160.h);
            if (checkHash(hash160))
            {
                setResultFound(index, true, privateKey, hash160.h);
            }
        }

        if (d_publicKeyCompressionTypeToCheck == PointCompressionType::UNCOMPRESSED || d_publicKeyCompressionTypeToCheck == PointCompressionType::BOTH)
        {
            readUInt256(d_publicKeyYPtr, i, publicY);

            hashPublicKey(publicX, publicY, hash160.h);
            if (checkHash(hash160))
            {
                setResultFound(index, false, privateKey, hash160.h);
            }
        }
    }
}

// Конвертирует uint256_t (little-endian) в формат байтов для secp256k1 (big-endian)
__device__ __forceinline__ void uint256_to_secp256k1_bytes(const uint256_t& src, uint8_t* dst)
{
    // secp256k1_scalar_set_b32 ожидает big-endian байты: b32[0] - старший байт, b32[31] - младший байт
    // uint256_t хранит little-endian: v[0] - младшие 32 бита, v[7] - старшие 32 бита
    const uint32_t* src_words = src.v;
    for (int i = 0; i < 8; ++i)
    {
        const uint32_t word = src_words[7 - i]; // Инвертируем порядок слов
        dst[i * 4 + 0] = (word >> 24) & 0xFF;  // Старший байт слова
        dst[i * 4 + 1] = (word >> 16) & 0xFF;
        dst[i * 4 + 2] = (word >> 8) & 0xFF;
        dst[i * 4 + 3] = word & 0xFF;           // Младший байт слова
    }
}

// Конвертирует результат secp256k1 (big-endian байты) в uint256_t (little-endian)
__device__ __forceinline__ void secp256k1_bytes_to_uint256(const uint8_t* src, uint256_t& dst)
{
    // secp256k1_pubkey_save возвращает big-endian байты: src[0] - старший байт, src[31] - младший байт
    // uint256_t хранит little-endian: v[0] - младшие 32 бита (little-endian слово), v[7] - старшие 32 бита (little-endian слово)
    uint32_t* dst_words = dst.v;
    for (int i = 0; i < 8; ++i)
    {
        const int byte_idx = 7 - i; // Инвертируем порядок слов
        // Создаем little-endian слово из big-endian байтов (инвертируем порядок байтов)
        dst_words[i] = (static_cast<uint32_t>(src[byte_idx * 4 + 3]) << 24) |
                       (static_cast<uint32_t>(src[byte_idx * 4 + 2]) << 16) |
                       (static_cast<uint32_t>(src[byte_idx * 4 + 1]) << 8) |
                       (static_cast<uint32_t>(src[byte_idx * 4 + 0]));
    }
}

__global__ void publicKeyGenerationKernel(const uint256_t *privateKeys)
{
    for(uint32_t i = 0; i < d_pointsPerThread; ++i)
    {
        HDExtendedPrivateKey privateExKey;
        HDExtendedPublicKey publicEXKey;

        uint256_t privateKey;
        readUInt256(privateKeys, i, privateKey);

        // Конвертируем uint256_t (little-endian) в формат для secp256k1 (big-endian байты)
        uint256_to_secp256k1_bytes(privateKey, privateExKey.key);
        
        generatePublicFromPrivateKey(&privateExKey, &publicEXKey);

        // Конвертируем результат secp256k1 (big-endian байты) в uint256_t (little-endian)
        uint256_t newX, newY;
        secp256k1_bytes_to_uint256(publicEXKey.key, newX);
        secp256k1_bytes_to_uint256(publicEXKey.key + 32, newY);

        writeUInt256(newX, i, d_publicKeyXPtr);
        writeUInt256(newY, i, d_publicKeyYPtr);
    }
}
