#include "atomic_list.cuh"
#include "defines.h"
#include "utils.cuh"

#include <cstdio>
#include <cstdlib>
#include <cstring>

__constant__ void *d_atomicListBuf[1];
__constant__ uint32_t *d_atomicListSize[1];


__device__ void atomicListAdd(const void *info, const uint32_t size)
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

    // malloc + cudaHostRegister: освобождаем через free(), не cudaFreeHost — не зависит от контекста CUDA при выходе
    h_countHostPtr = static_cast<uint32_t*>(malloc(sizeof(uint32_t)));
    if (!h_countHostPtr)
        cudaCheckError(cudaErrorMemoryAllocation);
    cudaCheckError(cudaHostRegister(h_countHostPtr, sizeof(uint32_t), cudaHostRegisterMapped));

    d_countDevPtr = nullptr;
    cudaCheckError(cudaHostGetDevicePointer(&d_countDevPtr, h_countHostPtr, 0));

    *h_countHostPtr = 0;

    const size_t dataSize = static_cast<size_t>(itemSize) * maxItems;
    h_hostPtr = malloc(dataSize);
    if (!h_hostPtr)
        cudaCheckError(cudaErrorMemoryAllocation);
    cudaCheckError(cudaHostRegister(h_hostPtr, dataSize, cudaHostRegisterMapped));

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
        uint32_t* p = h_countHostPtr;
        h_countHostPtr = nullptr;
        (void)cudaHostUnregister(p);
        free(p);
    }

    if (h_hostPtr != nullptr)
    {
        void* p = h_hostPtr;
        h_hostPtr = nullptr;
        (void)cudaHostUnregister(p);
        free(p);
    }
}
