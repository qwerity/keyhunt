#include "atomic_list.cuh"

#include <cuda_runtime.h>

static __constant__ void *_LIST_BUF[1];
static __constant__ uint *_LIST_SIZE[1];


__device__ void atomicListAdd(const void *info, const uint size)
{
    const uint count = atomicAdd(_LIST_SIZE[0], 1);
    unsigned char *ptr = static_cast<unsigned char *>(_LIST_BUF[0]) + count * size;
    memcpy(ptr, info, size);
}

static cudaError_t setListPtr(void *ptr, uint *numResults)
{
    if (const cudaError_t err = cudaMemcpyToSymbol(_LIST_BUF, &ptr, sizeof(void *)))
    {
        return err;
    }

    return cudaMemcpyToSymbol(_LIST_SIZE, &numResults, sizeof(uint *));
}

cudaError_t CudaAtomicList::init(uint itemSize, uint maxItems)
{
    _itemSize = itemSize;

    // The number of results found in the most recent kernel run
    _countHostPtr = nullptr;
    cudaError_t err = cudaHostAlloc(&_countHostPtr, sizeof(uint), cudaHostAllocMapped);
    if (err)
    {
        goto end;
    }

    // Number of items in the list
    _countDevPtr = nullptr;
    err = cudaHostGetDevicePointer(&_countDevPtr, _countHostPtr, 0);
    if (err)
    {
        goto end;
    }
    *_countHostPtr = 0;
    // Storage for results data
    _hostPtr = nullptr;
    err = cudaHostAlloc(&_hostPtr, itemSize * maxItems, cudaHostAllocMapped);
    if (err)
    {
        goto end;
    }
    // Storage for results data (device to host pointer)
    _devPtr = nullptr;
    err = cudaHostGetDevicePointer(&_devPtr, _hostPtr, 0);
    if (err)
    {
        goto end;
    }
    err = setListPtr(_devPtr, _countDevPtr);
end:
    if (err)
    {
        cudaFreeHost(_countHostPtr);
        cudaFree(_countDevPtr);
        cudaFreeHost(_hostPtr);
        cudaFree(_devPtr);
    }
    return err;
}

uint CudaAtomicList::size() const
{
    return *_countHostPtr;
}

void CudaAtomicList::clear() const
{
    *_countHostPtr = 0;
}

uint CudaAtomicList::read(void *dest, uint count) const
{
    if (count >= *_countHostPtr)
    {
        count = *_countHostPtr;
    }
    memcpy(dest, _hostPtr, count * _itemSize);
    return count;
}

void CudaAtomicList::cleanup() const
{
    cudaFreeHost(_countHostPtr);
    cudaFree(_countDevPtr);
    cudaFreeHost(_hostPtr);
    cudaFree(_devPtr);
}
