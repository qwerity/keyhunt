#pragma once

#include <cuda_runtime.h>
#include <cstdint>

#include "common_kernels.cuh"
#include "secp256k1_v2/bip39.cuh"

extern __constant__ int d_publicKeyCompressionTypeToCheck;

__constant__ uint32_t* d_mnemonicsSeedsPtr{};
__constant__ extended_private_key_t* d_mnemonicsSeedsMasterKeysPtr{};

__constant__ extended_public_key_t* d_publicKeysPtr{};
__constant__ extended_private_key_t* d_privateKeysPtr{};

__constant__ uint32_t* d_flattenedDerivationPathsPtr{};
__constant__ uint32_t* d_derivationPathsLengthsPtr{};
__constant__ uint32_t  d_derivationPathsNumber{};


struct HDWalletFunctor
{
    const uint8_t* mnemonics;

    __host__ __device__
    explicit HDWalletFunctor(const uint8_t* _mnemonics): mnemonics(_mnemonics)
    {}

    __device__
    void operator()(const uint32_t mnemonicIdx) const
    {
        // Get pointer to this thread's mnemonic and output area
        const uint8_t* mnemonic = mnemonics + (mnemonicIdx * SIZE_MNEMONIC_FRAME_12);
        extended_public_key_t* threadOutputs = d_publicKeysPtr + (mnemonicIdx * d_derivationPathsNumber);

        // Generate master key once for this mnemonic
        uint32_t seed[64 / 4]{};
        extended_private_key_t masterKey;
        mnemonicToExtendedMasterKey(mnemonic, seed, reinterpret_cast<uint8_t*>(&masterKey));

        // Process all paths for this mnemonic
        uint32_t pathOffset = 0;
        for (uint32_t pathIdx = 0; pathIdx < d_derivationPathsNumber; pathIdx++)
        {
            extended_private_key_t privateKey = masterKey;  // Start from master key
            extended_private_key_t tempKey;

            // Derive through current path
            for (uint32_t i = 0; i < d_derivationPathsLengthsPtr[pathIdx]; ++i)
            {
                uint32_t childIndex = d_flattenedDerivationPathsPtr[pathOffset + i];
                if (childIndex & 0x80000000)
                {
                    hardenedPrivateChildFromPrivate(&privateKey, &tempKey, childIndex & 0x7FFFFFFF);
                }
                else
                {
                    normalPrivateChildFromPrivate(&privateKey, &tempKey, childIndex);
                }
                privateKey = tempKey;
            }

            // Generate public key for this path
            generatePublicFromPrivateKey(&privateKey, &threadOutputs[pathIdx]);

            // Move to next path
            pathOffset += d_derivationPathsLengthsPtr[pathIdx];
        }
    }
};

__global__ void mnemonicsToExtendedMasterKeys(const uint8_t* mnemonics)
{
    const uint32_t idx = blockDim.x * blockIdx.x + threadIdx.x;

    // Get pointer to this thread's mnemonic and output area
    const uint8_t* mnemonic = mnemonics + (idx * SIZE_MNEMONIC_FRAME_12);

    // Generate master key once for this mnemonic
    uint32_t* seed = d_mnemonicsSeedsPtr + idx * (64 / 4);
    extended_private_key_t* masterKey = d_mnemonicsSeedsMasterKeysPtr + idx;
    mnemonicToExtendedMasterKey(mnemonic, seed, reinterpret_cast<uint8_t*>(masterKey));
}

__global__ void extendedMasterKeysToDerivatedPublicKeys()
{
    const uint32_t idx = blockDim.x * blockIdx.x + threadIdx.x;

    extended_public_key_t* mnemonicPublicKeys = d_publicKeysPtr + (idx * d_derivationPathsNumber);

    // Process all paths for this mnemonic
    uint32_t pathOffset = 0;
    for (uint32_t pathIdx = 0; pathIdx < d_derivationPathsNumber; ++pathIdx)
    {
        d_privateKeysPtr[idx] = d_mnemonicsSeedsMasterKeysPtr[idx];  // Start from master key

        // Derive through current path
        for (uint32_t i = 0; i < d_derivationPathsLengthsPtr[pathIdx]; ++i)
        {
            uint32_t childIndex = d_flattenedDerivationPathsPtr[pathOffset + i];
            if (childIndex & 0x80000000)
            {
                hardenedPrivateChildFromPrivate(d_privateKeysPtr + idx, d_privateKeysPtr + idx, childIndex & 0x7FFFFFFF);
            }
            else
            {
                normalPrivateChildFromPrivate(d_privateKeysPtr + idx, d_privateKeysPtr + idx, childIndex);
            }
        }

        // Generate public key for this path
        generatePublicFromPrivateKey(d_privateKeysPtr + idx, mnemonicPublicKeys + pathIdx);

        // Move to next path
        pathOffset += d_derivationPathsLengthsPtr[pathIdx];
    }
}

__global__ void hdWalletKernel(const uint8_t* mnemonics)
{
    const uint32_t idx = blockDim.x * blockIdx.x + threadIdx.x;
    //if (idx >= numMnemonics) return;

    // Get pointer to this thread's mnemonic and output area
    const uint8_t* mnemonic = mnemonics + (idx * SIZE_MNEMONIC_FRAME_12);
    extended_public_key_t* mnemonicPublicKeys = d_publicKeysPtr + (idx * d_derivationPathsNumber);

    // Generate master key once for this mnemonic
    uint32_t seed[64 / 4]{};
    extended_private_key_t masterKey;
    mnemonicToExtendedMasterKey(mnemonic, seed, reinterpret_cast<uint8_t*>(&masterKey));

    // Process all paths for this mnemonic
    uint32_t pathOffset = 0;
    for (uint32_t pathIdx = 0; pathIdx < d_derivationPathsNumber; ++pathIdx)
    {
        extended_private_key_t privateKey = masterKey;  // Start from master key

        // Derive through current path
        for (uint32_t i = 0; i < d_derivationPathsLengthsPtr[pathIdx]; ++i)
        {
            uint32_t childIndex = d_flattenedDerivationPathsPtr[pathOffset + i];
            if (childIndex & 0x80000000)
            {
                hardenedPrivateChildFromPrivate(&privateKey, &privateKey, childIndex & 0x7FFFFFFF);
            }
            else
            {
                normalPrivateChildFromPrivate(&privateKey, &privateKey, childIndex);
            }
        }

        // Generate public key for this path
        generatePublicFromPrivateKey(&privateKey, &mnemonicPublicKeys[pathIdx]);

        // Move to next path
        pathOffset += d_derivationPathsLengthsPtr[pathIdx];
    }
}

__global__ void checkExtendedPublicHashKernel()
{
    const uint32_t idx = blockDim.x * blockIdx.x + threadIdx.x;

    const extended_private_key_t *privateKey = d_privateKeysPtr + idx;
    const extended_public_key_t  *publicKey = d_publicKeysPtr + (idx * d_derivationPathsNumber);

    uint32_t uncompressedHash160Bytes[5];
    uint32_t compressedHash160Bytes[5];

    publicKeyToHash160(publicKey, uncompressedHash160Bytes, compressedHash160Bytes);

    if (d_publicKeyCompressionTypeToCheck == PointCompressionType::COMPRESSED || d_publicKeyCompressionTypeToCheck == PointCompressionType::BOTH)
    {
        if (checkHash(compressedHash160Bytes))
        {
            setResultFound(idx, true, privateKey->key, publicKey->key, compressedHash160Bytes);
        }
    }

    if (d_publicKeyCompressionTypeToCheck == PointCompressionType::UNCOMPRESSED || d_publicKeyCompressionTypeToCheck == PointCompressionType::BOTH)
    {
        if (checkHash(uncompressedHash160Bytes))
        {
            setResultFound(idx, false, privateKey->key, publicKey->key, uncompressedHash160Bytes);
        }
    }
}