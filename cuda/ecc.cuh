#pragma once

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

    void init(const thrust::host_vector<secp256k1::uint256>& privateKeys) const;

    [[nodiscard]] bool selfTest(const thrust::host_vector<secp256k1::uint256>& privateKeys) const;

    cudaError_t getResults(thrust::host_vector<std::pair<uint32_t, secp256k1::ecpoint>>& results) const;

    cudaError_t generatePublicKeys() const;

private:
    struct Impl;
    std::unique_ptr<Impl> mImpl;
};

