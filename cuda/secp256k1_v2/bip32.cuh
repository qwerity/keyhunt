#pragma once

#include <cuda_runtime.h>
#include <cstdint>

#define MNEMONIC_WORD_MAX_SIZE      (10)
#define NUM_WORDS_MNEMONIC          (12)
#define SIZE_MNEMONIC_FRAME_12      (MNEMONIC_WORD_MAX_SIZE * 12)
#define SIZE_MNEMONIC_FRAME_24      (MNEMONIC_WORD_MAX_SIZE * 24)
#define NUM_ENTROPY_FRAME           (111)
#define SIZE_ENTROPY_FRAME          (sizeof(uint64_t) * 2 * NUM_ENTROPY_FRAME)
#define SIZE32_MNEMONIC_FRAME       (128 / 4)
#define SIZE64_MNEMONIC_FRAME       (SIZE32_MNEMONIC_FRAME / 2)
#define SIZE_HASH160_FRAME          (20)
#define SIZE32_HASH160_FRAME        (SIZE_HASH160_FRAME / 4)
#define SIZE_MNEMONIC_SEED_FRAME    (64)
#define SIZE32_MNEMONIC_SEED_FRAME  (64 / 4)

struct alignas(32) extended_private_key_t
{
    uint8_t key[32]{};
    uint8_t chainCode[32]{};
};

struct alignas(32) extended_public_key_t
{
    uint8_t key[64]{};
};

__device__ void generatePublicFromPrivateKey(const extended_private_key_t* priv, extended_public_key_t* pub);

__device__ void compressedPublicKeyToHash160(const extended_public_key_t* pub, uint32_t* compressedHashBytes);
__device__ void publicKeyToHash160(const extended_public_key_t* pub, uint32_t* uncompressedHashBytes, uint32_t* compressedHashBytes);
__device__ void bip49_publicKeyToHash160(extended_public_key_t* pub, uint32_t* hash160Bytes);

__device__ void hardenedPrivateChildFromPrivate(const extended_private_key_t* parent, extended_private_key_t* child, uint16_t hardenedChildNumber);
__device__ void normalPrivateChildFromPrivate(const extended_private_key_t* parent, extended_private_key_t* child, uint16_t normalChildNumber);

/// for test purposes
__global__ void mnemonicToHash160(const uint8_t* mnemonic, uint8_t* masterExKey, uint32_t* seed,
                                  uint8_t* childKey, uint8_t* childChildKey, uint8_t* hardenedChildKey, uint16_t childNumber,
                                  extended_public_key_t* childPublicKey, uint32_t* uncompressedHash160Bytes, uint32_t* compressedHash160Bytes);
