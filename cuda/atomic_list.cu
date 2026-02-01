#include "atomic_list.cuh"
#include "defines.h"
#include "utils.cuh"

#include <cstdlib>
#include <cstring>

__constant__ void *d_atomicListBuf[1];
__constant__ uint32_t *d_atomicListSize[1];


/** maxrregcount(64) so this can be called from kernels with __launch_bounds__(256, 4) (64 regs). */
__device__ __attribute__((maxrregcount(64))) void atomicListAdd(const void *info, const uint32_t size)
{
    const uint32_t count = atomicAdd(d_atomicListSize[0], 1);
    uint8_t *ptr = static_cast<uint8_t *>(d_atomicListBuf[0]) + count * size;
    cuda_memcpy(ptr, static_cast<const uint8_t*>(info), size);
}

static void setListPtr(void *ptr, uint32_t *numResults)
{
    cudaCheckError(cudaMemcpyToSymbol(d_atomicListBuf, &ptr, sizeof(void *)));
    cudaCheckError(cudaMemcpyToSymbol(d_atomicListSize, &numResults, sizeof(uint32_t *)));
}

void CudaAtomicList::init(const uint32_t itemSize, const uint32_t maxItems)
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
