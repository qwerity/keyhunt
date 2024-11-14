#pragma once

#include "util/common_host.h"
#include "util/cuda_util.h"

#include <memory>

// Wallet structure
// m / purpose' / coin_type' / account' / change / address_index

class HDWallet
{
public:
    explicit HDWallet(const std::shared_ptr<GlobalContext>& context, cu::CudaDeviceInfo&& cudaInfo);
    ~HDWallet();

    HDWallet(const HDWallet&) = delete;
    HDWallet& operator=(const HDWallet&) = delete;

    HDWallet(HDWallet&& rhs) noexcept;
    HDWallet& operator=(HDWallet&& rhs) noexcept;

    void startSearchPublicHash() const;

private:
    struct Impl;
    std::unique_ptr<Impl> mImpl;
};