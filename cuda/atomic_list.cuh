#pragma once

#include <cstdint>
#include <cuda_runtime.h>

/** Callable from kernels with max 64 regs (e.g. __launch_bounds__(256, 4)); implementation uses maxrregcount(64). */
__device__ void atomicListAdd(const void *info, uint32_t size);

/**
 A list that multiple device threads can append items to. Items can be
 read and removed by the host
 */
class CudaAtomicList
{
public:
    CudaAtomicList() = default;
    ~CudaAtomicList()
    {
        cleanup();
    }

    void init(uint32_t itemSize, uint32_t maxItems);

    uint32_t read(void *dest, uint32_t count) const;
    [[nodiscard]] uint32_t size() const;
    void clear() const;
    void cleanup() const;

private:
    void *d_devPtr{nullptr};
    void *h_hostPtr{nullptr};

    uint32_t *h_countHostPtr{nullptr};
    uint32_t *d_countDevPtr{nullptr};

    uint32_t h_maxSize{0};
    uint32_t h_itemSize{0};
};
