#include "cuda_util.h"
#include "common.h"

namespace cu
{
    CudaDeviceInfo getDeviceInfo(int device)
    {
        cudaDeviceProp properties{};
        safeCall(cudaSetDevice(device));
        safeCall(cudaGetDeviceProperties(&properties, device));

        CudaDeviceInfo devInfo;
        devInfo.id = device;
        devInfo.name = std::string(properties.name);
        devInfo.major = properties.major;
        devInfo.minor = properties.minor;

        devInfo.multiProcessorCount = properties.multiProcessorCount;
        devInfo.maxThreadsPerMultiProcessor = properties.maxThreadsPerMultiProcessor;
        devInfo.warpSize = properties.warpSize;
        devInfo.maxThreadsPerBlock = properties.maxThreadsPerBlock;
        devInfo.persistingL2CacheMaxSize = properties.persistingL2CacheMaxSize;
        devInfo.l2CacheSize = properties.l2CacheSize;
        devInfo.globalL1CacheSupported = properties.globalL1CacheSupported;
        devInfo.localL1CacheSupported = properties.localL1CacheSupported;
        devInfo.mem = properties.totalGlobalMem;

        int cores = 0;
        switch (devInfo.major)
        {
            case 1:
                cores = 8;
            break;
            case 2:
                if (devInfo.minor == 0)
                {
                    cores = 32;
                } else
                {
                    cores = 48;
                }
            break;
            case 3:
                cores = 192;
            break;
            case 5:
                cores = 128;
            break;
            case 6:
                if (devInfo.minor == 1 || devInfo.minor == 2)
                {
                    cores = 128;
                } else
                {
                    cores = 64;
                }
            break;
            case 7:
                cores = 64;
            break;
            default:
                cores = 8;
            break;
        }
        devInfo.cores = cores;
        return devInfo;
    }


    std::vector<CudaDeviceInfo> getDevices()
    {
        const int count = getDeviceCount();
        std::vector<CudaDeviceInfo> devList;
        for (int device = 0; device < count; device++)
        {
            devList.push_back(getDeviceInfo(device));
        }
        return devList;
    }

    int getDeviceCount()
    {
        int count = 0;
        if (const cudaError_t err = cudaGetDeviceCount(&count))
        {
            throw CudaException(err);
        }
        return count;
    }

    void printDeviceInfo(const CudaDeviceInfo& info)
    {
        printf("ID:     %d\n", info.id);
        printf("Name:   %s\n", info.name.c_str());
        printf("Minor: %d, Major: %d\n", info.major, info.minor);
        printf("Capability: %d%d\n", info.major, info.minor);
        printf("warpSize: %d\n", info.warpSize);
        printf("Memory: %luMB\n", info.mem / MB);
        printf("multiProcessorCount: %d\n", info.multiProcessorCount);
        printf("maxThreadsPerMultiProcessor: %d\n", info.maxThreadsPerMultiProcessor);
        printf("globalL1CacheSupported: %d\n", info.globalL1CacheSupported);
        printf("localL1CacheSupported: %d\n", info.localL1CacheSupported);
        printf("l2CacheSize: %d\n", info.l2CacheSize);
        printf("persistingL2CacheMaxSize: %d\n", info.persistingL2CacheMaxSize);
        printf("\n");
    }

    void cudaInit(const int cudaDeviceId)
    {
        safeCall(cudaSetDevice(cudaDeviceId));
        safeCall(cudaSetDeviceFlags(cudaDeviceScheduleBlockingSync));

        // Use a larger portion of shared memory for L1 cache
        safeCall(cudaDeviceSetCacheConfig(cudaFuncCachePreferL1));
    }
}
