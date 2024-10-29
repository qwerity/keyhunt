#pragma once

#include <cuda_runtime.h>
#include <cstdint>

__device__ void mnemonicToExtendedPrivateKey(const uint8_t* mnemonic, uint32_t seed[64 / 4], uint8_t* extended_private_key);