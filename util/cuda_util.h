#pragma once

#include <cuda_runtime.h>
#include <stdexcept>

#include <string>
#include <vector>

namespace cu
{
    struct CudaDeviceInfo
    {
        int id{};
        int major{};
        int minor{};
        int multiProcessorCount{};
        int maxThreadsPerMultiProcessor{};
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

    class CudaException final : std::exception
    {
    public:
        explicit CudaException(const cudaError_t err) : error(err)
        {
            msg_ = std::string(cudaGetErrorString(err));
        }

        [[nodiscard]] cudaError_t getCudaError() const
        {
            return error;
        }

        [[nodiscard]] const char* what() const noexcept override
        {
            return msg_.c_str();
        }

    private:
        cudaError_t error{cudaSuccess};
        std::string msg_;
    };

    inline void safeCall(const cudaError_t err) noexcept(false)
    {
        if (err)
        {
            printf("%s\n", cudaGetErrorString(err));
            throw CudaException(err);
        }
    }

    CudaDeviceInfo getDeviceInfo(int device);
    std::vector<CudaDeviceInfo> getDevices();
    int getDeviceCount();
    void printDeviceInfo(const CudaDeviceInfo& info);

    void cudaInit(int cudaDeviceId);
}