#pragma once

#include <cuda_runtime.h>

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

    cudaError_t init(uint32_t itemSize, uint32_t maxItems);

    uint32_t read(void *dest, uint32_t count) const;
    [[nodiscard]] uint32_t size() const;
    void clear() const;
    void cleanup() const;

private:
    void *_devPtr{nullptr};
    void *_hostPtr{nullptr};

    uint32_t *_countHostPtr{nullptr};
    uint32_t *_countDevPtr{nullptr};

    uint32_t _maxSize{0};
    uint32_t _itemSize{0};
};
