#pragma once

#include <cstdint>
#include <cuda_runtime.h>

// Exposed for inline result write (avoids atomicListAdd's 70 regs in hot path)
extern __constant__ void *d_atomicListBuf[1];
extern __constant__ uint32_t *d_atomicListSize[1];

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
