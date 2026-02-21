#pragma once

#include "defines.cuh"

#include <cstddef>
#include <memory>
#include <unordered_set>

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

    /// Set targets from contiguous array (no internal copy; use from C API / Rust to avoid duplicate storage).
    void setTargets(const hash160* targets, size_t count) const;

    /// Set targets from callback (zero temp allocation; getter(user_data, index, out) fills *out).
    using Hash160Getter = void (*)(const void* user_data, size_t index, hash160* out);
    void setTargets(size_t count, const void* user_data, Hash160Getter getter) const;

private:
    struct Impl;
    std::unique_ptr<Impl> mImpl;
};
