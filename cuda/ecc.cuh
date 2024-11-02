#pragma once

#include "defines.cuh"

#include <vector>
#include <memory>

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

    void calculatePublicKeysAndCheckHash160() const;
    void generatePrivateKeysForXPerIteration(uint32_t privateXPart, uint32_t iteration) const;

    /// TODO(ksh): somehow this function doesn't exported to the lib code, to figure out later
    /// so disabling this interface for the moment
    /// void getPrivateKeys(thrust::host_vector<uint256_t>& h_privateKeys) const;

    void getPrivateKeys(std::vector<uint256_t>& h_privateKeys) const;

private:
    struct Impl;
    std::unique_ptr<Impl> mImpl;
};

