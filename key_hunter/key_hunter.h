#pragma once

#include "util/cuda_util.h"
#include "util/common_host.h"

class KeyHunter
{
public:
    explicit KeyHunter(const std::shared_ptr<GlobalContext>& context, cu::CudaDeviceInfo&& cudaInfo);
    ~KeyHunter();

    KeyHunter(KeyHunter& rhs) = delete;
    KeyHunter& operator=(KeyHunter& rhs) = delete;

    KeyHunter(KeyHunter&& rhs) noexcept;
    KeyHunter& operator=(KeyHunter&& rhs) noexcept;

    void startSearchPublicHash() const;
    void stop() const;

private:
    struct Impl;
    std::unique_ptr<Impl> mImpl;
};
