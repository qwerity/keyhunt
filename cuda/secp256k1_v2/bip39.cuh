#pragma once

#include <cuda_runtime.h>
#include <cstdint>

__device__ void mnemonicToExtendedMasterKey(const uint8_t* mnemonic, uint32_t* seed, uint8_t* extendedMasterKey);