#pragma once

#include "defines.cuh"
#include <thrust/host_vector.h>

class ECC
{
public:
    ECC();
    ~ECC();

    ECC(const ECC&) = delete;
    ECC& operator=(const ECC&) = delete;

    ECC(ECC&& rhs) noexcept;
    ECC& operator=(ECC&& rhs) noexcept;

    void setGPoints(const std::vector<ecpoint_t>& h_GPoints) const;

    void initWithPrivateDefinedXRandomY(uint32_t pointsPerThread, uint32_t publicKeyCompressionTypeToCheck, uint32_t blockSize = 0) const;

    [[nodiscard]] uint32_t getKeysNumberPerIteration() const;

    cudaError_t getResults(thrust::host_vector<std::pair<uint256_t, ecpoint_t>>& results) const;

    void calculatePublicKeys() const;
    void generatePrivateKeysForXPerIteration(const uint32_t privateXPart, const uint32_t iteration) const;

    void getPrivateKeys(thrust::host_vector<uint256_t>& h_privateKeys) const;

private:
    struct Impl;
    std::unique_ptr<Impl> mImpl;
};

