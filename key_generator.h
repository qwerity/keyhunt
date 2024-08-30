#pragma once
#include <thread>

#include "util/common.h"

class KeyGenerator : public std::thread
{
public:
    explicit KeyGenerator(const Context& context);
    ~KeyGenerator();

    KeyGenerator(KeyGenerator& rhs) = delete;
    KeyGenerator& operator=(KeyGenerator& rhs) = delete;

    KeyGenerator(KeyGenerator&& rhs) noexcept;
    KeyGenerator& operator=(KeyGenerator&& rhs) noexcept;

    void start(const thrust::host_vector<secp256k1::uint256>& privateKeys) const;
    void startRandom(uint32_t keysNumberToGenerate = 5) const;
    void stop() const;

    [[nodiscard]] bool isDone() const;

    void selfTest(uint32_t keysNumberToGenerate = 5) const;

private:
    struct Impl;
    std::unique_ptr<Impl> mImpl;
};
