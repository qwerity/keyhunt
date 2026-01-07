#pragma once

#include <cuda_runtime.h>
#include <cstdint>

#include "common_kernels.cuh"
#include "secp256k1_v2/bip39.cuh"

extern __constant__ int d_publicKeyCompressionTypeToCheck;

__constant__ uint32_t* d_mnemonicsSeedsPtr{};
__constant__ HDExtendedPrivateKey* d_mnemonicsMasterKeysPtr{};

__constant__ HDExtendedPublicKey*  d_mnemonicsPublicKeysPtr{};
__constant__ HDExtendedPrivateKey* d_mnemonicsPrivateKeysPtr{};

__constant__ uint32_t* d_hdWalletFlattenedDerivationPathsPtr{};
__constant__ uint32_t* d_hdWalletDerivationPathsLengthsPtr{};
__constant__ uint32_t  d_hdWalletDerivationPathsNumber{};

__constant__ HDExtendedPrivateKey* d_mnemonicsIntermediatePrivateKeysPtr{};
__constant__ uint32_t  d_hdWalletAccountsToGenerate{};
__constant__ uint32_t  d_hdWalletAddressesToGenerate{};

__device__ __forceinline__ void setResultFound(const uint32_t idx, const bool compressed,
                                               const HDExtendedPrivateKey* exMasterKey, const uint32_t digest[5],
                                               const uint32_t derivedPathIndex)
{
    Hash160MnemonicSearchCudaResult r;
    r.block = blockIdx.x;
    r.thread = threadIdx.x;
    r.idx = idx;
    r.compressed = compressed;

    r.masterKey = *exMasterKey;
    r.derivedPathIndex = derivedPathIndex;

    // digest уже в правильном формате (little-endian) из publicKeyToHash160
    #pragma unroll
    for (uint32_t i = 0; i < 5; ++i)
    {
        r.digest[i] = digest[i];
    }

    atomicListAdd(&r, sizeof(r));
}

__global__ void mnemonicsToExtendedMasterKeysKernel(const uint8_t* mnemonics)
{
    const uint32_t idx = blockDim.x * blockIdx.x + threadIdx.x;

    // Get pointer to this thread's mnemonic and output area
    const uint8_t* mnemonic = mnemonics + (idx * SIZE_MNEMONIC_FRAME_12);

    // Generate master key once for this mnemonic
    uint32_t* seed = d_mnemonicsSeedsPtr + idx * SIZE32_SEED;
    HDExtendedPrivateKey* masterKey = d_mnemonicsMasterKeysPtr + idx;
    mnemonicToExtendedMasterKey(mnemonic, seed, reinterpret_cast<uint8_t*>(masterKey));
}

__global__ void extendedMasterKeysToDerivatedPublicKeysKernel()
{
    const uint32_t idx = blockDim.x * blockIdx.x + threadIdx.x;

    HDExtendedPublicKey* mnemonicPublicKeys = d_mnemonicsPublicKeysPtr + (idx * d_hdWalletDerivationPathsNumber);

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
    HDExtendedPublicKey* publicKeys = d_mnemonicsPublicKeysPtr + (idx * d_hdWalletDerivationPathsNumber);

    // Generate master key once for this mnemonic
    uint32_t* seed = d_mnemonicsSeedsPtr + idx * SIZE32_SEED;
    HDExtendedPrivateKey* masterKey = d_mnemonicsMasterKeysPtr + idx;
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
        generatePublicFromPrivateKey(d_mnemonicsPrivateKeysPtr + idx, publicKeys + pathIdx);

        // Move to next path
        pathOffset += d_hdWalletDerivationPathsLengthsPtr[pathIdx];
    }
}

__global__ void hdWalletBTCKernel(const uint8_t* mnemonics)
{
    const uint32_t idx = blockDim.x * blockIdx.x + threadIdx.x;

    // Get pointer to this thread's mnemonic and output area
    const uint8_t* mnemonic = mnemonics + (idx * SIZE_MNEMONIC_FRAME_12);
    HDExtendedPrivateKey* outPrivateKey = d_mnemonicsPrivateKeysPtr + (idx * d_hdWalletDerivationPathsNumber);
    HDExtendedPublicKey* outPublicKeys = d_mnemonicsPublicKeysPtr + (idx * d_hdWalletDerivationPathsNumber);

    HDExtendedPrivateKey* m_privateKeys_int = d_mnemonicsIntermediatePrivateKeysPtr + (idx * d_hdWalletAccountsToGenerate * d_hdWalletAddressesToGenerate);

    // Generate master key once for this mnemonic
    uint32_t* seed = d_mnemonicsSeedsPtr + idx * SIZE32_SEED;
    HDExtendedPrivateKey* outMasterKey = d_mnemonicsMasterKeysPtr + idx;
    mnemonicToExtendedMasterKey(mnemonic, seed, reinterpret_cast<uint8_t*>(outMasterKey));

    // "m/max(addr, acc)" - private keys
    #pragma unroll
    for (uint32_t i = 0; i < max(d_hdWalletAccountsToGenerate, d_hdWalletAddressesToGenerate); ++i)
    {
        normalPrivateChildFromPrivate(outMasterKey, m_privateKeys_int + i, i);
    }

    // "m/addr" - public keys
    #pragma unroll
    for (uint32_t i = 0; i < d_hdWalletAddressesToGenerate; ++i)
    {
        outPrivateKey[i] = m_privateKeys_int[i];
        generatePublicFromPrivateKey(m_privateKeys_int + i, outPublicKeys + i);
    }
    outPrivateKey += d_hdWalletAddressesToGenerate;
    outPublicKeys += d_hdWalletAddressesToGenerate;

    // m/0/0 - tmp_privateKey[0]
    // m/1/0 - tmp_privateKey[addressesToGenerate]
    HDExtendedPrivateKey* tmp_privateKey = outPrivateKey;

    // "m/acc/addr"
    #pragma unroll
    for (uint32_t i = 0; i < d_hdWalletAccountsToGenerate; ++i)
    {
        for (uint32_t j = 0; j < d_hdWalletAddressesToGenerate; ++j)
        {
            normalPrivateChildFromPrivate(m_privateKeys_int + i, outPrivateKey + i * d_hdWalletAddressesToGenerate + j, j);
            generatePublicFromPrivateKey(outPrivateKey + i * d_hdWalletAddressesToGenerate + j, outPublicKeys + i * d_hdWalletAddressesToGenerate + j);
        }
    }
    outPublicKeys += d_hdWalletAccountsToGenerate * d_hdWalletAddressesToGenerate;
    outPrivateKey += d_hdWalletAccountsToGenerate * d_hdWalletAddressesToGenerate;

    // "m/acc/0/addr"
    #pragma unroll
    for (uint32_t i = 0; i < d_hdWalletAccountsToGenerate; ++i)
    {
        for (uint32_t j = 0; j < d_hdWalletAddressesToGenerate; ++j)
        {
            normalPrivateChildFromPrivate(tmp_privateKey + i * d_hdWalletAddressesToGenerate, outPrivateKey + i * d_hdWalletAddressesToGenerate + j, j);
            generatePublicFromPrivateKey(outPrivateKey + i * d_hdWalletAddressesToGenerate + j, outPublicKeys + i * d_hdWalletAddressesToGenerate + j);
        }
    }
    outPublicKeys += d_hdWalletAccountsToGenerate * d_hdWalletAddressesToGenerate;
    outPrivateKey += d_hdWalletAccountsToGenerate * d_hdWalletAddressesToGenerate;

    // "m/acc'/addr"
    #pragma unroll
    for (uint32_t i = 0; i < d_hdWalletAccountsToGenerate; ++i)
    {
        hardenedPrivateChildFromPrivate(outMasterKey, m_privateKeys_int + i, i);
    }

    // m/0'/0 - tmp_privateKey[0]
    // m/1'/0 - tmp_privateKey[addressesToGenerate]
    // ...
    tmp_privateKey = outPrivateKey;

    #pragma unroll
    for (uint32_t i = 0; i < d_hdWalletAccountsToGenerate; ++i)
    {
        for (uint32_t j = 0; j < d_hdWalletAddressesToGenerate; ++j)
        {
            normalPrivateChildFromPrivate(m_privateKeys_int + i, outPrivateKey + i * d_hdWalletAddressesToGenerate + j, j);
            generatePublicFromPrivateKey(outPrivateKey + i * d_hdWalletAddressesToGenerate + j, outPublicKeys + i * d_hdWalletAddressesToGenerate + j);
        }
    }
    outPublicKeys += d_hdWalletAccountsToGenerate * d_hdWalletAddressesToGenerate;
    outPrivateKey += d_hdWalletAccountsToGenerate * d_hdWalletAddressesToGenerate;

    // "m/acc'/0/addr"
    #pragma unroll
    for (uint32_t i = 0; i < d_hdWalletAccountsToGenerate; ++i)
    {
        for (uint32_t j = 0; j < d_hdWalletAddressesToGenerate; ++j)
        {
            normalPrivateChildFromPrivate(tmp_privateKey + i * d_hdWalletAddressesToGenerate, outPrivateKey + i * d_hdWalletAddressesToGenerate + j, j);
            generatePublicFromPrivateKey(outPrivateKey + i * d_hdWalletAddressesToGenerate + j, outPublicKeys + i * d_hdWalletAddressesToGenerate + j);
        }
    }
    outPublicKeys += d_hdWalletAccountsToGenerate * d_hdWalletAddressesToGenerate;
    outPrivateKey += d_hdWalletAccountsToGenerate * d_hdWalletAddressesToGenerate;

    // "m/44'/acc'/0/addr"
    HDExtendedPrivateKey m_44h_privateKeys;
    hardenedPrivateChildFromPrivate(outMasterKey, &m_44h_privateKeys, 44);

    // "m/44'/acc'
    #pragma unroll
    for (uint32_t i = 0; i < d_hdWalletAccountsToGenerate; ++i)
    {
        hardenedPrivateChildFromPrivate(&m_44h_privateKeys, m_privateKeys_int + i, i);
    }

    #pragma unroll
    for (uint32_t i = 0; i < d_hdWalletAccountsToGenerate; ++i)
    {
        normalPrivateChildFromPrivate(m_privateKeys_int + i, m_privateKeys_int + i, 0);
        for (uint32_t j = 0; j < d_hdWalletAddressesToGenerate; ++j)
        {
            normalPrivateChildFromPrivate(m_privateKeys_int + i, outPrivateKey + i * d_hdWalletAddressesToGenerate + j, j);
            generatePublicFromPrivateKey(outPrivateKey + i * d_hdWalletAddressesToGenerate + j, outPublicKeys + i * d_hdWalletAddressesToGenerate + j);
        }
    }
    outPublicKeys += d_hdWalletAccountsToGenerate * d_hdWalletAddressesToGenerate;
    outPrivateKey += d_hdWalletAccountsToGenerate * d_hdWalletAddressesToGenerate;


    // "m/44'/0'/acc'/0/addr"
    HDExtendedPrivateKey m_44h_0h_privateKey;
    hardenedPrivateChildFromPrivate(&m_44h_privateKeys, &m_44h_0h_privateKey, 0);

    // "m/44'/0'/acc'/0
    #pragma unroll
    for (uint32_t i = 0; i < d_hdWalletAccountsToGenerate; ++i)
    {
        hardenedPrivateChildFromPrivate(&m_44h_0h_privateKey, m_privateKeys_int + i, i);
        normalPrivateChildFromPrivate(m_privateKeys_int + i, m_privateKeys_int + i, 0);
    }

    #pragma unroll
    for (uint32_t i = 0; i < d_hdWalletAccountsToGenerate; ++i)
    {
        for (uint32_t j = 0; j < d_hdWalletAddressesToGenerate; ++j)
        {
            normalPrivateChildFromPrivate(m_privateKeys_int + i, outPrivateKey + i * d_hdWalletAddressesToGenerate + j, j);
            generatePublicFromPrivateKey(outPrivateKey + i * d_hdWalletAddressesToGenerate + j, outPublicKeys + i * d_hdWalletAddressesToGenerate + j);
        }
    }
    outPublicKeys += d_hdWalletAccountsToGenerate * d_hdWalletAddressesToGenerate;
    outPrivateKey += d_hdWalletAccountsToGenerate * d_hdWalletAddressesToGenerate;

    // "m/44'/145'/acc'/0/addr"
    HDExtendedPrivateKey m_44h_145h_privateKey;
    hardenedPrivateChildFromPrivate(&m_44h_privateKeys, &m_44h_145h_privateKey, 145);

    // "m/44'/145'/acc'/0
    #pragma unroll
    for (uint32_t i = 0; i < d_hdWalletAccountsToGenerate; ++i)
    {
        hardenedPrivateChildFromPrivate(&m_44h_145h_privateKey, m_privateKeys_int + i, i);
        normalPrivateChildFromPrivate(m_privateKeys_int + i, m_privateKeys_int + i, 0);
    }
    #pragma unroll
    for (uint32_t i = 0; i < d_hdWalletAccountsToGenerate; ++i)
    {
        for (uint32_t j = 0; j < d_hdWalletAddressesToGenerate; ++j)
        {
            normalPrivateChildFromPrivate(m_privateKeys_int + i, outPrivateKey + i * d_hdWalletAddressesToGenerate + j, j);
            generatePublicFromPrivateKey(outPrivateKey + i * d_hdWalletAddressesToGenerate + j, outPublicKeys + i * d_hdWalletAddressesToGenerate + j);
        }
    }
    outPublicKeys += d_hdWalletAccountsToGenerate * d_hdWalletAddressesToGenerate;
    outPrivateKey += d_hdWalletAccountsToGenerate * d_hdWalletAddressesToGenerate;


    // "m/44'/156'/acc'/0/addr"
    HDExtendedPrivateKey m_44h_156h_privateKey;
    hardenedPrivateChildFromPrivate(&m_44h_privateKeys, &m_44h_156h_privateKey, 156);

    // "m/44'/156'/acc'/0
    #pragma unroll
    for (uint32_t i = 0; i < d_hdWalletAccountsToGenerate; ++i)
    {
        hardenedPrivateChildFromPrivate(&m_44h_156h_privateKey, m_privateKeys_int + i, i);
        normalPrivateChildFromPrivate(m_privateKeys_int + i, m_privateKeys_int + i, 0);
    }
    #pragma unroll
    for (uint32_t i = 0; i < d_hdWalletAccountsToGenerate; ++i)
    {
        for (uint32_t j = 0; j < d_hdWalletAddressesToGenerate; ++j)
        {
            normalPrivateChildFromPrivate(m_privateKeys_int + i, outPrivateKey + i * d_hdWalletAddressesToGenerate + j, j);
            generatePublicFromPrivateKey(outPrivateKey + i * d_hdWalletAddressesToGenerate + j, outPublicKeys + i * d_hdWalletAddressesToGenerate + j);
        }
    }
    outPublicKeys += d_hdWalletAccountsToGenerate * d_hdWalletAddressesToGenerate;
    outPrivateKey += d_hdWalletAccountsToGenerate * d_hdWalletAddressesToGenerate;

    // "m/44'/236'/acc'/0/addr"
    HDExtendedPrivateKey m_44h_236h_privateKey;
    hardenedPrivateChildFromPrivate(&m_44h_privateKeys, &m_44h_236h_privateKey, 236);

    // "m/44'/236'/acc'/0
    #pragma unroll
    for (uint32_t i = 0; i < d_hdWalletAccountsToGenerate; ++i)
    {
        hardenedPrivateChildFromPrivate(&m_44h_236h_privateKey, m_privateKeys_int + i, i);
        normalPrivateChildFromPrivate(m_privateKeys_int + i, m_privateKeys_int + i, 0);
    }
    #pragma unroll
    for (uint32_t i = 0; i < d_hdWalletAccountsToGenerate; ++i)
    {
        for (uint32_t j = 0; j < d_hdWalletAddressesToGenerate; ++j)
        {
            normalPrivateChildFromPrivate(m_privateKeys_int + i, outPrivateKey + i * d_hdWalletAddressesToGenerate + j, j);
            generatePublicFromPrivateKey(outPrivateKey + i * d_hdWalletAddressesToGenerate + j, outPublicKeys + i * d_hdWalletAddressesToGenerate + j);
        }
    }
    outPublicKeys += d_hdWalletAccountsToGenerate * d_hdWalletAddressesToGenerate;
    outPrivateKey += d_hdWalletAccountsToGenerate * d_hdWalletAddressesToGenerate;

    // "m/44'/999'/acc'/0/addr"
    HDExtendedPrivateKey m_44h_999h_privateKey;
    hardenedPrivateChildFromPrivate(&m_44h_privateKeys, &m_44h_999h_privateKey, 999);

    // "m/44'/999'/acc'/0
    #pragma unroll
    for (uint32_t i = 0; i < d_hdWalletAccountsToGenerate; ++i)
    {
        hardenedPrivateChildFromPrivate(&m_44h_999h_privateKey, m_privateKeys_int + i, i);
        normalPrivateChildFromPrivate(m_privateKeys_int + i, m_privateKeys_int + i, 0);
    }
    #pragma unroll
    for (uint32_t i = 0; i < d_hdWalletAccountsToGenerate; ++i)
    {
        for (uint32_t j = 0; j < d_hdWalletAddressesToGenerate; ++j)
        {
            normalPrivateChildFromPrivate(m_privateKeys_int + i, outPrivateKey + i * d_hdWalletAddressesToGenerate + j, j);
            generatePublicFromPrivateKey(outPrivateKey + i * d_hdWalletAddressesToGenerate + j, outPublicKeys + i * d_hdWalletAddressesToGenerate + j);
        }
    }
    outPublicKeys += d_hdWalletAccountsToGenerate * d_hdWalletAddressesToGenerate;
    outPrivateKey += d_hdWalletAccountsToGenerate * d_hdWalletAddressesToGenerate;


    // "m/49'/0'/acc'/0/addr"
    HDExtendedPrivateKey m_49h_privateKeys;
    hardenedPrivateChildFromPrivate(outMasterKey, &m_49h_privateKeys, 49);

    // "m/49'/0'"
    HDExtendedPrivateKey m_49h_0h_privateKeys;
    hardenedPrivateChildFromPrivate(&m_49h_privateKeys, &m_49h_0h_privateKeys, 0);

    // "m/49'/0'/acc'/0
    #pragma unroll
    for (uint32_t i = 0; i < d_hdWalletAccountsToGenerate; ++i)
    {
        hardenedPrivateChildFromPrivate(&m_49h_0h_privateKeys, m_privateKeys_int + i, i);
        normalPrivateChildFromPrivate(m_privateKeys_int + i, m_privateKeys_int + i, 0);
    }
    #pragma unroll
    for (uint32_t i = 0; i < d_hdWalletAccountsToGenerate; ++i)
    {
        for (uint32_t j = 0; j < d_hdWalletAddressesToGenerate; ++j)
        {
            normalPrivateChildFromPrivate(m_privateKeys_int + i, outPrivateKey + i * d_hdWalletAddressesToGenerate + j, j);
            generatePublicFromPrivateKey(outPrivateKey + i * d_hdWalletAddressesToGenerate + j, outPublicKeys + i * d_hdWalletAddressesToGenerate + j);
        }
    }
    outPublicKeys += d_hdWalletAccountsToGenerate * d_hdWalletAddressesToGenerate;
    outPrivateKey += d_hdWalletAccountsToGenerate * d_hdWalletAddressesToGenerate;

    // "m/49'/145'/acc'/0/addr"
    // "m/49'/145'"
    HDExtendedPrivateKey m_49h_145h_privateKeys;
    hardenedPrivateChildFromPrivate(&m_49h_privateKeys, &m_49h_145h_privateKeys, 145);

    // "m/49'/145'/acc'/0
    #pragma unroll
    for (uint32_t i = 0; i < d_hdWalletAccountsToGenerate; ++i)
    {
        hardenedPrivateChildFromPrivate(&m_49h_145h_privateKeys, m_privateKeys_int + i, i);
        normalPrivateChildFromPrivate(m_privateKeys_int + i, m_privateKeys_int + i, 0);
    }
    #pragma unroll
    for (uint32_t i = 0; i < d_hdWalletAccountsToGenerate; ++i)
    {
        for (uint32_t j = 0; j < d_hdWalletAddressesToGenerate; ++j)
        {
            normalPrivateChildFromPrivate(m_privateKeys_int + i, outPrivateKey + i * d_hdWalletAddressesToGenerate + j, j);
            generatePublicFromPrivateKey(outPrivateKey + i * d_hdWalletAddressesToGenerate + j, outPublicKeys + i * d_hdWalletAddressesToGenerate + j);
        }
    }
    outPublicKeys += d_hdWalletAccountsToGenerate * d_hdWalletAddressesToGenerate;
    outPrivateKey += d_hdWalletAccountsToGenerate * d_hdWalletAddressesToGenerate;

    // "m/49'/156'/acc'/0/addr"
    // "m/49'/156'"
    HDExtendedPrivateKey m_49h_156h_privateKeys;
    hardenedPrivateChildFromPrivate(&m_49h_privateKeys, &m_49h_156h_privateKeys, 156);

    // "m/49'/156'/acc'/0
    #pragma unroll
    for (uint32_t i = 0; i < d_hdWalletAccountsToGenerate; ++i)
    {
        hardenedPrivateChildFromPrivate(&m_49h_156h_privateKeys, m_privateKeys_int + i, i);
        normalPrivateChildFromPrivate(m_privateKeys_int + i, m_privateKeys_int + i, 0);
    }
    #pragma unroll
    for (uint32_t i = 0; i < d_hdWalletAccountsToGenerate; ++i)
    {
        for (uint32_t j = 0; j < d_hdWalletAddressesToGenerate; ++j)
        {
            normalPrivateChildFromPrivate(m_privateKeys_int + i, outPrivateKey + i * d_hdWalletAddressesToGenerate + j, j);
            generatePublicFromPrivateKey(outPrivateKey + i * d_hdWalletAddressesToGenerate + j, outPublicKeys + i * d_hdWalletAddressesToGenerate + j);
        }
    }
    outPublicKeys += d_hdWalletAccountsToGenerate * d_hdWalletAddressesToGenerate;
    outPrivateKey += d_hdWalletAccountsToGenerate * d_hdWalletAddressesToGenerate;

    // "m/49'/236'/acc'/0/addr"
    // "m/49'/236'"
    HDExtendedPrivateKey m_49h_236h_privateKeys;
    hardenedPrivateChildFromPrivate(&m_49h_privateKeys, &m_49h_236h_privateKeys, 236);

    // "m/49'/236'/acc'/0
    #pragma unroll
    for (uint32_t i = 0; i < d_hdWalletAccountsToGenerate; ++i)
    {
        hardenedPrivateChildFromPrivate(&m_49h_236h_privateKeys, m_privateKeys_int + i, i);
        normalPrivateChildFromPrivate(m_privateKeys_int + i, m_privateKeys_int + i, 0);
    }
    #pragma unroll
    for (uint32_t i = 0; i < d_hdWalletAccountsToGenerate; ++i)
    {
        for (uint32_t j = 0; j < d_hdWalletAddressesToGenerate; ++j)
        {
            normalPrivateChildFromPrivate(m_privateKeys_int + i, outPrivateKey + i * d_hdWalletAddressesToGenerate + j, j);
            generatePublicFromPrivateKey(outPrivateKey + i * d_hdWalletAddressesToGenerate + j, outPublicKeys + i * d_hdWalletAddressesToGenerate + j);
        }
    }
    outPublicKeys += d_hdWalletAccountsToGenerate * d_hdWalletAddressesToGenerate;
    outPrivateKey += d_hdWalletAccountsToGenerate * d_hdWalletAddressesToGenerate;

    // "m/49'/999'/acc'/0/addr"
    // "m/49'/999'"
    HDExtendedPrivateKey m_49h_999h_privateKeys;
    hardenedPrivateChildFromPrivate(&m_49h_privateKeys, &m_49h_999h_privateKeys, 999);

    // "m/49'/999'/acc'/0
    #pragma unroll
    for (uint32_t i = 0; i < d_hdWalletAccountsToGenerate; ++i)
    {
        hardenedPrivateChildFromPrivate(&m_49h_999h_privateKeys, m_privateKeys_int + i, i);
        normalPrivateChildFromPrivate(m_privateKeys_int + i, m_privateKeys_int + i, 0);
    }
    #pragma unroll
    for (uint32_t i = 0; i < d_hdWalletAccountsToGenerate; ++i)
    {
        for (uint32_t j = 0; j < d_hdWalletAddressesToGenerate; ++j)
        {
            normalPrivateChildFromPrivate(m_privateKeys_int + i, outPrivateKey + i * d_hdWalletAddressesToGenerate + j, j);
            generatePublicFromPrivateKey(outPrivateKey + i * d_hdWalletAddressesToGenerate + j, outPublicKeys + i * d_hdWalletAddressesToGenerate + j);
        }
    }
    outPublicKeys += d_hdWalletAccountsToGenerate * d_hdWalletAddressesToGenerate;
    outPrivateKey += d_hdWalletAccountsToGenerate * d_hdWalletAddressesToGenerate;

    // "m/84'/0'/acc'/0/addr"
    HDExtendedPrivateKey m_84h_privateKeys;
    hardenedPrivateChildFromPrivate(outMasterKey, &m_84h_privateKeys, 84);

    // "m/84'/0'"
    HDExtendedPrivateKey m_84h_0h_privateKeys;
    hardenedPrivateChildFromPrivate(&m_84h_privateKeys, &m_84h_0h_privateKeys, 0);

    // "m/84'/0'/acc'/0
    #pragma unroll
    for (uint32_t i = 0; i < d_hdWalletAccountsToGenerate; ++i)
    {
        hardenedPrivateChildFromPrivate(&m_84h_0h_privateKeys, m_privateKeys_int + i, i);
        normalPrivateChildFromPrivate(m_privateKeys_int + i, m_privateKeys_int + i, 0);
    }
    #pragma unroll
    for (uint32_t i = 0; i < d_hdWalletAccountsToGenerate; ++i)
    {
        for (uint32_t j = 0; j < d_hdWalletAddressesToGenerate; ++j)
        {
            normalPrivateChildFromPrivate(m_privateKeys_int + i, outPrivateKey + i * d_hdWalletAddressesToGenerate + j, j);
            generatePublicFromPrivateKey(outPrivateKey + i * d_hdWalletAddressesToGenerate + j, outPublicKeys + i * d_hdWalletAddressesToGenerate + j);
        }
    }
    outPublicKeys += d_hdWalletAccountsToGenerate * d_hdWalletAddressesToGenerate;
    outPrivateKey += d_hdWalletAccountsToGenerate * d_hdWalletAddressesToGenerate;

    // "m/86'/0'/acc'/0/addr"
    HDExtendedPrivateKey m_86h_privateKeys;
    hardenedPrivateChildFromPrivate(outMasterKey, &m_86h_privateKeys, 86);

    // "m/86'/0'"
    HDExtendedPrivateKey m_86h_0h_privateKeys;
    hardenedPrivateChildFromPrivate(&m_86h_privateKeys, &m_86h_0h_privateKeys, 0);

    // "m/86'/0'/acc'/0
    #pragma unroll
    for (uint32_t i = 0; i < d_hdWalletAccountsToGenerate; ++i)
    {
        hardenedPrivateChildFromPrivate(&m_86h_0h_privateKeys, m_privateKeys_int + i, i);
        normalPrivateChildFromPrivate(m_privateKeys_int + i, m_privateKeys_int + i, 0);
    }
    #pragma unroll
    for (uint32_t i = 0; i < d_hdWalletAccountsToGenerate; ++i)
    {
        for (uint32_t j = 0; j < d_hdWalletAddressesToGenerate; ++j)
        {
            normalPrivateChildFromPrivate(m_privateKeys_int + i, outPrivateKey + i * d_hdWalletAddressesToGenerate + j, j);
            generatePublicFromPrivateKey(outPrivateKey + i * d_hdWalletAddressesToGenerate + j, outPublicKeys + i * d_hdWalletAddressesToGenerate + j);
        }
    }
//    outPublicKeys += accountsToGenerate * addressesToGenerate;
//    outPrivateKey += accountsToGenerate * addressesToGenerate;
}

__global__ void checkExtendedPublicHashKernel()
{
    const uint32_t idx = blockDim.x * blockIdx.x + threadIdx.x;

    const HDExtendedPrivateKey* privateKey = d_mnemonicsPrivateKeysPtr + idx;
    const HDExtendedPublicKey* publicKeys = d_mnemonicsPublicKeysPtr + (idx * d_hdWalletDerivationPathsNumber);

    uint32_t uncompressedHash160Bytes[5];
    uint32_t compressedHash160Bytes[5];

    for (uint32_t pathIndex = 0; pathIndex < d_hdWalletDerivationPathsNumber; ++pathIndex)
    {
        publicKeyToHash160(publicKeys + pathIndex, uncompressedHash160Bytes, compressedHash160Bytes);

        if (d_publicKeyCompressionTypeToCheck == PointCompressionType::COMPRESSED || d_publicKeyCompressionTypeToCheck == PointCompressionType::BOTH)
        {
            if (checkHash(compressedHash160Bytes))
            {
                setResultFound(idx, true, privateKey, compressedHash160Bytes, pathIndex);
            }
        }

        if (d_publicKeyCompressionTypeToCheck == PointCompressionType::UNCOMPRESSED || d_publicKeyCompressionTypeToCheck == PointCompressionType::BOTH)
        {
            if (checkHash(uncompressedHash160Bytes))
            {
                setResultFound(idx, false, privateKey, uncompressedHash160Bytes, pathIndex);
            }
        }
    }
}