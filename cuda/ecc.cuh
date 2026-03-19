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

    void init(uint32_t pointsPerThread, uint32_t publicKeyCompressionTypeToCheck, uint32_t generatorMode = 1, uint32_t gridSize = 0, uint32_t blockSize = 0) const;

    [[nodiscard]] uint32_t getKeysNumberPerIteration() const;

    void calculatePublicKeysAndCheckHash160() const;
    /** Fills d_publicKeysX/Y so that getPublicKeys() returns valid data (e.g. for tests). Not used by key search path. */
    void fillPublicKeys() const;
    void generatePrivateKeysForXPerIteration(uint32_t privateXPart, uint32_t iteration) const;

    // ---------- Double-buffer pipeline API ----------
    // Step 1: generate private keys into the STAGING buffer asynchronously.
    //         Returns immediately; GPU key-gen runs on mInitStream.
    void pregenerateKeysAsync(uint32_t privateXPart, uint32_t iteration) const;

    // Step 2: sync mInitStream (wait for key-gen), swap buffers, launch the
    //         hash-check kernel on the CURRENT buffer async (mGeneratorStream).
    //         Returns immediately; kernel runs in background.
    void launchKernelAsync() const;

    // Step 3: sync mGeneratorStream (wait for kernel).
    void syncKernel() const;

    void getPrivateKeys(std::vector<uint256_t>& h_privateKeys) const;
    /** Valid only after fillPublicKeys(). After calculatePublicKeysAndCheckHash160() public keys are not written to global memory. */
    void getPublicKeys(std::vector<uint256_t>& h_publicKeysX, std::vector<uint256_t>& h_publicKeysY) const;
    
    void setPrivateKeys(const std::vector<uint256_t>& h_privateKeys) const;

private:
    struct Impl;
    std::unique_ptr<Impl> mImpl;
};
