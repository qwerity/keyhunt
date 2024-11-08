#pragma once

#include "defines.cuh"

#include <unordered_set>
#include <memory>

__device__ bool checkHash(const uint32_t hash[5]);
__device__ bool checkHash(const hash160& hash);

class Hash160Lookup
{
public:
    Hash160Lookup();
    ~Hash160Lookup();

    Hash160Lookup(const Hash160Lookup&) = delete;
    Hash160Lookup& operator=(const Hash160Lookup&) = delete;

    Hash160Lookup(Hash160Lookup&& rhs) noexcept;
    Hash160Lookup& operator=(Hash160Lookup&& rhs) noexcept;

    void setTargets(const std::unordered_set<hash160> &hash160Targets) const;

private:
    struct Impl;
    std::unique_ptr<Impl> mImpl;
};
