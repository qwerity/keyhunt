#pragma once

#include "defines.cuh"
#include "udevice_vector.cuh"

#include "secp256k1.h"

class ECC
{
public:
    ECC();
    ~ECC();

    ECC(const ECC&) = delete;
    ECC& operator=(const ECC&) = delete;

    ECC(ECC&& rhs) noexcept;
    ECC& operator=(ECC&& rhs) noexcept;

    void init(uint32_t pointsPerThread, const thrust::host_vector<secp256k1::uint256>& privateKeys) const;
    void initWithPrivateDefinedXRandomY(uint32_t pointsPerThread, uint32_t blockSize = 0) const;

    [[nodiscard]] uint32_t getKeysNumberPerIteration() const;

    [[nodiscard]] bool selfTest(const thrust::host_vector<secp256k1::uint256>& privateKeys) const;

    cudaError_t getResults(thrust::host_vector<std::pair<uint256_t, secp256k1::ecpoint>> &results) const;

    [[nodiscard]] cudaError_t calculatePublicKeys() const;
    void generatePrivateKeysForXPerIteration(uint privateXPart, uint iteration) const;

    void getPrivateKeys(thrust::host_vector<uint256_t>& h_privateKeys) const;

private:
    struct Impl;
    std::unique_ptr<Impl> mImpl;
};

