#pragma once

#include <cuda_runtime.h>

__device__ void atomicListAdd(const void *info, uint size);

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

    cudaError_t init(uint itemSize, uint maxItems);

    uint read(void *dest, uint count) const;
    [[nodiscard]] uint size() const;
    void clear() const;
    void cleanup() const;

private:
    void *_devPtr{nullptr};
    void *_hostPtr{nullptr};

    uint *_countHostPtr{nullptr};
    uint *_countDevPtr{nullptr};

    uint _maxSize{0};
    uint _itemSize{0};
};
