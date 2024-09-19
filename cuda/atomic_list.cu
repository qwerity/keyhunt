#include "atomic_list.cuh"

static __constant__ void *d_listBuf[1];
static __constant__ uint32_t *d_listSize[1];


__device__ void atomicListAdd(const void *info, const uint32_t size)
{
    const uint32_t count = atomicAdd(d_listSize[0], 1);
    unsigned char *ptr = static_cast<unsigned char *>(d_listBuf[0]) + count * size;
    memcpy(ptr, info, size);
}

static cudaError_t setListPtr(void *ptr, uint32_t *numResults)
{
    if (const cudaError_t err = cudaMemcpyToSymbol(d_listBuf, &ptr, sizeof(void *)))
    {
        return err;
    }

    return cudaMemcpyToSymbol(d_listSize, &numResults, sizeof(uint32_t *));
}

cudaError_t CudaAtomicList::init(uint32_t itemSize, uint32_t maxItems)
{
    _itemSize = itemSize;

    // The number of results found in the most recent kernel run
    _countHostPtr = nullptr;
    cudaError_t err = cudaHostAlloc(&_countHostPtr, sizeof(uint32_t), cudaHostAllocMapped);
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

uint32_t CudaAtomicList::size() const
{
    return *_countHostPtr;
}

void CudaAtomicList::clear() const
{
    *_countHostPtr = 0;
}

uint32_t CudaAtomicList::read(void *dest, uint32_t count) const
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
