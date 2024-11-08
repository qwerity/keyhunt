#pragma once

#include <cuda_runtime.h>
#include <cstdint>

#include "common_kernels.cuh"
#include "secp256k1_v2/bip39.cuh"

extern __constant__ int d_publicKeyCompressionTypeToCheck;

__constant__ inline uint32_t* d_mnemonicsSeedsPtr{};
__constant__ inline extended_private_key_t* d_mnemonicsMasterKeysPtr{};

__constant__ inline extended_public_key_t*  d_mnemonicsPublicKeysPtr{};
__constant__ inline extended_private_key_t* d_mnemonicsPrivateKeysPtr{};

__constant__ inline uint32_t* d_hdWalletFlattenedDerivationPathsPtr{};
__constant__ inline uint32_t* d_hdWalletDerivationPathsLengthsPtr{};
__constant__ inline uint32_t  d_hdWalletDerivationPathsNumber{};

__global__ void mnemonicsToExtendedMasterKeys(const uint8_t* mnemonics)
{
    const uint32_t idx = blockDim.x * blockIdx.x + threadIdx.x;

    // Get pointer to this thread's mnemonic and output area
    const uint8_t* mnemonic = mnemonics + (idx * SIZE_MNEMONIC_FRAME_12);

    // Generate master key once for this mnemonic
    uint32_t* seed = d_mnemonicsSeedsPtr + idx * (64 / 4);
    extended_private_key_t* masterKey = d_mnemonicsMasterKeysPtr + idx;
    mnemonicToExtendedMasterKey(mnemonic, seed, reinterpret_cast<uint8_t*>(masterKey));
}

__global__ void extendedMasterKeysToDerivatedPublicKeys()
{
    const uint32_t idx = blockDim.x * blockIdx.x + threadIdx.x;

    extended_public_key_t* mnemonicPublicKeys = d_mnemonicsPublicKeysPtr + (idx * d_hdWalletDerivationPathsNumber);

    // Process all paths for this mnemonic
    uint32_t pathOffset = 0;
    for (uint32_t pathIdx = 0; pathIdx < d_hdWalletDerivationPathsNumber; ++pathIdx)
    {
        d_mnemonicsPrivateKeysPtr[idx] = d_mnemonicsMasterKeysPtr[idx];  // Start from master key

        // Derive through current path
        for (uint32_t i = 0; i < d_hdWalletDerivationPathsLengthsPtr[pathIdx]; ++i)
        {
            const uint32_t childIndex = d_hdWalletFlattenedDerivationPathsPtr[pathOffset + i];
            if (childIndex & 0x80000000)
            {
                hardenedPrivateChildFromPrivate(d_mnemonicsPrivateKeysPtr + idx, d_mnemonicsPrivateKeysPtr + idx, childIndex & 0x7FFFFFFF);
            }
            else
            {
                normalPrivateChildFromPrivate(d_mnemonicsPrivateKeysPtr + idx, d_mnemonicsPrivateKeysPtr + idx, childIndex);
            }
        }

        // Generate public key for this path
        generatePublicFromPrivateKey(d_mnemonicsPrivateKeysPtr + idx, mnemonicPublicKeys + pathIdx);

        // Move to next path
        pathOffset += d_hdWalletDerivationPathsLengthsPtr[pathIdx];
    }
}

__global__ void hdWalletKernel(const uint8_t* mnemonics)
{
    const uint32_t idx = blockDim.x * blockIdx.x + threadIdx.x;

    // Get pointer to this thread's mnemonic and output area
    const uint8_t* mnemonic = mnemonics + (idx * SIZE_MNEMONIC_FRAME_12);
    extended_public_key_t* mnemonicPublicKeys = d_mnemonicsPublicKeysPtr + (idx * d_hdWalletDerivationPathsNumber);

    // Generate master key once for this mnemonic
    uint32_t* seed = d_mnemonicsSeedsPtr + idx * (64 / 4);
    extended_private_key_t* masterKey = d_mnemonicsMasterKeysPtr + idx;
    mnemonicToExtendedMasterKey(mnemonic, seed, reinterpret_cast<uint8_t*>(masterKey));

    // Process all paths for this mnemonic
    uint32_t pathOffset = 0;
    for (uint32_t pathIdx = 0; pathIdx < d_hdWalletDerivationPathsNumber; ++pathIdx)
    {
        d_mnemonicsPrivateKeysPtr[idx] = d_mnemonicsMasterKeysPtr[idx];  // Start from master key

        // Derive through current path
        for (uint32_t i = 0; i < d_hdWalletDerivationPathsLengthsPtr[pathIdx]; ++i)
        {
            const uint32_t childIndex = d_hdWalletFlattenedDerivationPathsPtr[pathOffset + i];
            if (childIndex & 0x80000000)
            {
                hardenedPrivateChildFromPrivate(d_mnemonicsPrivateKeysPtr + idx, d_mnemonicsPrivateKeysPtr + idx, childIndex & 0x7FFFFFFF);
            }
            else
            {
                normalPrivateChildFromPrivate(d_mnemonicsPrivateKeysPtr + idx, d_mnemonicsPrivateKeysPtr + idx, childIndex);
            }
        }

        // Generate public key for this path
        generatePublicFromPrivateKey(d_mnemonicsPrivateKeysPtr + idx, mnemonicPublicKeys + pathIdx);

        // Move to next path
        pathOffset += d_hdWalletDerivationPathsLengthsPtr[pathIdx];
    }
}

__global__ void checkExtendedPublicHashKernel()
{
    const uint32_t idx = blockDim.x * blockIdx.x + threadIdx.x;

    const extended_private_key_t *privateKey = d_mnemonicsPrivateKeysPtr + idx;
    const extended_public_key_t  *publicKey = d_mnemonicsPublicKeysPtr + (idx * d_hdWalletDerivationPathsNumber);

    uint32_t uncompressedHash160Bytes[5];
    uint32_t compressedHash160Bytes[5];
    publicKeyToHash160(publicKey, uncompressedHash160Bytes, compressedHash160Bytes);

    if (d_publicKeyCompressionTypeToCheck == PointCompressionType::COMPRESSED || d_publicKeyCompressionTypeToCheck == PointCompressionType::BOTH)
    {
        if (checkHash(compressedHash160Bytes))
        {
            setResultFound(idx, true, privateKey->key, compressedHash160Bytes);
        }
    }

    if (d_publicKeyCompressionTypeToCheck == PointCompressionType::UNCOMPRESSED || d_publicKeyCompressionTypeToCheck == PointCompressionType::BOTH)
    {
        if (checkHash(uncompressedHash160Bytes))
        {
            setResultFound(idx, false, privateKey->key, uncompressedHash160Bytes);
        }
    }
}
