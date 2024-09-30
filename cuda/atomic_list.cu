#include "atomic_list.cuh"

#include "util/common.h"

static __constant__ void *d_listBuf[1];
static __constant__ uint32_t *d_listSize[1];


__device__ void atomicListAdd(const void *info, const uint32_t size)
{
    const uint32_t count = atomicAdd(d_listSize[0], 1);
    unsigned char *ptr = static_cast<unsigned char *>(d_listBuf[0]) + count * size;
    memcpy(ptr, info, size);
}

static void setListPtr(void *ptr, uint32_t *numResults)
{
    cudaCheckError(cudaMemcpyToSymbol(d_listBuf, &ptr, sizeof(void *)));
    cudaCheckError(cudaMemcpyToSymbol(d_listSize, &numResults, sizeof(uint32_t *)));
}

void CudaAtomicList::init(uint32_t itemSize, uint32_t maxItems)
{
    h_itemSize = itemSize;

    // The number of results found in the most recent kernel run
    h_countHostPtr = nullptr;
    cudaCheckError(cudaHostAlloc(&h_countHostPtr, sizeof(uint32_t), cudaHostAllocMapped));

    // Number of items in the list
    d_countDevPtr = nullptr;
    cudaCheckError(cudaHostGetDevicePointer(&d_countDevPtr, h_countHostPtr, 0));

    *h_countHostPtr = 0;
    // Storage for results data
    h_hostPtr = nullptr;
    cudaCheckError(cudaHostAlloc(&h_hostPtr, itemSize * maxItems, cudaHostAllocMapped));

    // Storage for results data (device to host pointer)
    d_devPtr = nullptr;
    cudaCheckError(cudaHostGetDevicePointer(&d_devPtr, h_hostPtr, 0));

    setListPtr(d_devPtr, d_countDevPtr);
}

uint32_t CudaAtomicList::size() const
{
    return *h_countHostPtr;
}

void CudaAtomicList::clear() const
{
    *h_countHostPtr = 0;
}

uint32_t CudaAtomicList::read(void *dest, uint32_t count) const
{
    if (count >= *h_countHostPtr)
    {
        count = *h_countHostPtr;
    }

    memcpy(dest, h_hostPtr, count * h_itemSize);
    return count;
}

void CudaAtomicList::cleanup() const
{
    if (h_countHostPtr != nullptr)
    {
        cudaCheckError(cudaFreeHost(h_countHostPtr));
    }

    if (h_hostPtr != nullptr)
    {
        cudaCheckError(cudaFreeHost(h_hostPtr));
    }
}
