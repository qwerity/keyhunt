#pragma once

#include <cuda_runtime.h>
#include <cstdint>

__device__ void hmacSHA512(const uint32_t* key, const uint32_t* message, uint32_t* output);