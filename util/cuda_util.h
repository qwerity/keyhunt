#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace cu
{
    struct CudaDeviceInfo
    {
        int id{};
        int major{};
        int minor{};
        int multiProcessorCount{};
        int maxThreadsPerMultiProcessor{};
        size_t totalConstMem{};
        size_t sharedMemPerBlock{};
        size_t sharedMemPerBlockOptin{};
        size_t sharedMemPerMultiprocessor{};
        size_t reservedSharedMemPerBlock{};
        int warpSize{};
        int cores{};
        uint64_t mem{};
        std::string name;
        int maxThreadsPerBlock{};
        int l2CacheSize{};
        int localL1CacheSupported{};
        int persistingL2CacheMaxSize{};
        int globalL1CacheSupported{};
    };

    CudaDeviceInfo getDeviceInfo(int device);
    std::vector<CudaDeviceInfo> getDevices();
    int getDeviceCount();
    void printDeviceInfo(const CudaDeviceInfo& info);

    CudaDeviceInfo cudaInit(int cudaDeviceId);
}
