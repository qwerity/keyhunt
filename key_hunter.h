#pragma once
#include <thread>

#include "util/common.h"

class KeyHunter
{
public:
    explicit KeyHunter(const AppConfig& config);
    ~KeyHunter();

    KeyHunter(KeyHunter& rhs) = delete;
    KeyHunter& operator=(KeyHunter& rhs) = delete;

    KeyHunter(KeyHunter&& rhs) noexcept;
    KeyHunter& operator=(KeyHunter&& rhs) noexcept;

    void start(const thrust::host_vector<secp256k1::uint256>& privateKeys, uint32_t pointsPerThread = 32) const;
    void startWithRandomPrivateKeys() const;
    void stop() const;

    [[nodiscard]] bool isDone() const;

    void selfTest(uint32_t keysNumberToGenerate = 5) const;

private:
    struct Impl;
    std::unique_ptr<Impl> mImpl;
};
