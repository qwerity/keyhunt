#pragma once

#include "../defines.h"

#include <cuda_runtime.h>

#define SIZE_MNEMONIC_FRAME_12      (128u)
#define SIZE_MNEMONIC_FRAME_24      (SIZE_MNEMONIC_FRAME_12 * 2u)
#define NUM_ENTROPY_FRAME           (111)
#define SIZE_ENTROPY_FRAME          (sizeof(uint64_t) * 2 * NUM_ENTROPY_FRAME)
#define SIZE32_MNEMONIC_FRAME_12    (SIZE_MNEMONIC_FRAME_12 / 4)
#define SIZE64_MNEMONIC_FRAME       (SIZE_MNEMONIC_FRAME_12 / 2)
#define SIZE_HASH160_FRAME          (20)
#define SIZE32_HASH160_FRAME        (SIZE_HASH160_FRAME / 4)
#define SIZE_SHA512_HMAC            (64)
#define SIZE32_SHA512_HMAC          (64 / 4)
#define SIZE32_SEED                 SIZE32_SHA512_HMAC


__device__ void generatePublicFromPrivateKey(const HDExtendedPrivateKey* priv, HDExtendedPublicKey* pub);

__device__ void compressedPublicKeyToHash160(const HDExtendedPublicKey* pub, uint32_t* compressedHashBytes);
__device__ void publicKeyToHash160(const HDExtendedPublicKey* pub, uint32_t* uncompressedHashBytes, uint32_t* compressedHashBytes);
__device__ void bip49_publicKeyToHash160(const HDExtendedPublicKey* pub, uint32_t* hash160Bytes);

__device__ void hardenedPrivateChildFromPrivate(const HDExtendedPrivateKey* parent, HDExtendedPrivateKey* child, uint32_t hardenedChildNumber);
__device__ void normalPrivateChildFromPrivate(const HDExtendedPrivateKey* parent, HDExtendedPrivateKey* child, uint32_t normalChildNumber);

/// for test purposes
__global__ void mnemonicToHash160(const uint8_t* mnemonic, uint8_t* masterExKey, uint32_t* seed,
                                  uint8_t* childKey, uint8_t* childChildKey, uint8_t* hardenedChildKey, uint32_t childNumber,
                                  HDExtendedPublicKey* childPublicKey, uint32_t* uncompressedHash160Bytes, uint32_t* compressedHash160Bytes);
