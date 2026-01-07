#include "ecc_helper.cuh"
#include "common_kernels.cuh"

#include "secp256k1_v2/bip32.cuh"
#include "secp256k1_v2/secp256k1.cuh"

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

// Максимально оптимизированная версия: конвертирует uint256_t напрямую в формат для secp256k1_scalar_set_b32
// Использует прямой доступ к памяти и развернутые циклы для максимальной производительности
__device__ __forceinline__ void uint256_to_secp256k1_bytes_optimized(const uint256_t& src, uint8_t* dst)
{
    // secp256k1_scalar_set_b32 ожидает big-endian байты: b32[0] - старший байт, b32[31] - младший байт
    // uint256_t хранит little-endian: v[0] - младшие 32 бита, v[7] - старшие 32 бита
    // Разворачиваем цикл полностью для максимальной производительности
    const uint32_t* v = src.v;
    
    // v[7] -> dst[0..3] (старшие байты)
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
    
    // v[0] -> dst[28..31] (младшие байты)
    const uint32_t w0 = v[0];
    dst[28] = static_cast<uint8_t>(w0 >> 24);
    dst[29] = static_cast<uint8_t>(w0 >> 16);
    dst[30] = static_cast<uint8_t>(w0 >> 8);
    dst[31] = static_cast<uint8_t>(w0);
}

// Максимально оптимизированная версия: конвертирует результат secp256k1 напрямую в uint256_t
// Использует прямой доступ к памяти и развернутые циклы для максимальной производительности
__device__ __forceinline__ void secp256k1_bytes_to_uint256_optimized(const uint8_t* src, uint256_t& dst)
{
    // secp256k1_pubkey_save возвращает big-endian байты: src[0] - старший байт, src[31] - младший байт
    // uint256_t хранит little-endian: v[0] - младшие 32 бита, v[7] - старшие 32 бита
    // Разворачиваем цикл полностью для максимальной производительности
    uint32_t* v = dst.v;
    
    // src[28..31] -> v[0] (младшие байты, инвертируем порядок байтов)
    v[0] = (static_cast<uint32_t>(src[31]) << 24) |
           (static_cast<uint32_t>(src[30]) << 16) |
           (static_cast<uint32_t>(src[29]) << 8) |
           (static_cast<uint32_t>(src[28]));
    
    // src[24..27] -> v[1]
    v[1] = (static_cast<uint32_t>(src[27]) << 24) |
           (static_cast<uint32_t>(src[26]) << 16) |
           (static_cast<uint32_t>(src[25]) << 8) |
           (static_cast<uint32_t>(src[24]));
    
    // src[20..23] -> v[2]
    v[2] = (static_cast<uint32_t>(src[23]) << 24) |
           (static_cast<uint32_t>(src[22]) << 16) |
           (static_cast<uint32_t>(src[21]) << 8) |
           (static_cast<uint32_t>(src[20]));
    
    // src[16..19] -> v[3]
    v[3] = (static_cast<uint32_t>(src[19]) << 24) |
           (static_cast<uint32_t>(src[18]) << 16) |
           (static_cast<uint32_t>(src[17]) << 8) |
           (static_cast<uint32_t>(src[16]));
    
    // src[12..15] -> v[4]
    v[4] = (static_cast<uint32_t>(src[15]) << 24) |
           (static_cast<uint32_t>(src[14]) << 16) |
           (static_cast<uint32_t>(src[13]) << 8) |
           (static_cast<uint32_t>(src[12]));
    
    // src[8..11] -> v[5]
    v[5] = (static_cast<uint32_t>(src[11]) << 24) |
           (static_cast<uint32_t>(src[10]) << 16) |
           (static_cast<uint32_t>(src[9]) << 8) |
           (static_cast<uint32_t>(src[8]));
    
    // src[4..7] -> v[6]
    v[6] = (static_cast<uint32_t>(src[7]) << 24) |
           (static_cast<uint32_t>(src[6]) << 16) |
           (static_cast<uint32_t>(src[5]) << 8) |
           (static_cast<uint32_t>(src[4]));
    
    // src[0..3] -> v[7] (старшие байты, инвертируем порядок байтов)
    v[7] = (static_cast<uint32_t>(src[3]) << 24) |
           (static_cast<uint32_t>(src[2]) << 16) |
           (static_cast<uint32_t>(src[1]) << 8) |
           (static_cast<uint32_t>(src[0]));
}

__global__ void publicKeyGenerationKernel(const uint256_t *privateKeys)
{
    // Оптимизация: используем batch normalization если d_pointsPerThread <= 16
    // Это позволяет нормализовать несколько точек одновременно, используя batch inversion
    constexpr uint32_t MAX_BATCH_SIZE = 16;
    
    if (d_pointsPerThread <= MAX_BATCH_SIZE)
    {
        // Batch mode: собираем все точки в якобиановых координатах, затем нормализуем batch'ом
        secp256k1_gej points[MAX_BATCH_SIZE];
        secp256k1_ge normalized_points[MAX_BATCH_SIZE];
        
        // Шаг 1: Вычислить все точки в якобиановых координатах (без нормализации)
        // Примечание: #pragma unroll не работает для динамических циклов (d_pointsPerThread - runtime значение)
        // Компилятор может оптимизировать цикл автоматически через loop unrolling для небольших значений
        for(uint32_t i = 0; i < d_pointsPerThread; ++i)
        {
            HDExtendedPrivateKey privateExKey;
            uint256_t privateKey;
            readUInt256(privateKeys, i, privateKey);
            
            // Оптимизированная конвертация: используем inline функции с #pragma unroll
            uint256_to_secp256k1_bytes_optimized(privateKey, privateExKey.key);
            
            // Вычислить точку в якобиановых координатах (без нормализации)
            secp256k1_ec_pubkey_create_gej(&points[i], &privateExKey.key[0]);
        }
        
        // Шаг 2: Нормализовать все точки batch'ом (1 инверсия вместо N)
        secp256k1_ge_set_gej_batch(normalized_points, points, d_pointsPerThread);
        
        // Шаг 3: Сохранить результаты
        for(uint32_t i = 0; i < d_pointsPerThread; ++i)
        {
            // Конвертировать нормализованные точки в формат для сохранения
            uint8_t pubkey[64];
            secp256k1_pubkey_save(pubkey, &normalized_points[i]);
            
            // Оптимизированная конвертация результата
            uint256_t newX, newY;
            secp256k1_bytes_to_uint256_optimized(pubkey, newX);
            secp256k1_bytes_to_uint256_optimized(pubkey + 32, newY);
            
            writeUInt256(newX, i, d_publicKeyXPtr);
            writeUInt256(newY, i, d_publicKeyYPtr);
        }
    }
    else
    {
        // Fallback: обычный метод для больших batch'ей (когда d_pointsPerThread > 16)
        // Разбиваем на батчи по 16 элементов
        for(uint32_t batchStart = 0; batchStart < d_pointsPerThread; batchStart += MAX_BATCH_SIZE)
        {
            const uint32_t batchSize = (MAX_BATCH_SIZE < (d_pointsPerThread - batchStart)) ? MAX_BATCH_SIZE : (d_pointsPerThread - batchStart);
            secp256k1_gej points[MAX_BATCH_SIZE];
            secp256k1_ge normalized_points[MAX_BATCH_SIZE];
            
            // Вычислить точки в текущем батче
            for(uint32_t i = 0; i < batchSize; ++i)
            {
                HDExtendedPrivateKey privateExKey;
                uint256_t privateKey;
                readUInt256(privateKeys, batchStart + i, privateKey);
                
                uint256_to_secp256k1_bytes_optimized(privateKey, privateExKey.key);
                secp256k1_ec_pubkey_create_gej(&points[i], &privateExKey.key[0]);
            }
            
            // Нормализовать batch'ом
            secp256k1_ge_set_gej_batch(normalized_points, points, batchSize);
            
            // Сохранить результаты
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
