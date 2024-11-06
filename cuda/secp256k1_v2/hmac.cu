#include "hmac.cuh"
#include "sha.cuh"

__device__ void hmacSHA512(const uint32_t* key, const uint32_t* message, uint32_t* output)
{
    alignas(32) uint32_t ipadKey[128 / 4]{};
    alignas(32) uint32_t opadKey[128 / 4]{};

    #pragma unroll
    for (int x = 0; x < 32 / 4; x++)
    {
        ipadKey[x] = 0x36363636 ^ *(key + x);
        opadKey[x] = 0x5C5C5C5C ^ *(key + x);
    }

    #pragma unroll
    for (int x = 32 / 4; x < 128 / 4; x++)
    {
        ipadKey[x] = 0x36363636;
        opadKey[x] = 0x5C5C5C5C;
    }

    alignas(32) uint32_t innerConcat[256 / 4]{};

    #pragma unroll
    for (int x = 0; x < 128 / 4; x++)
    {
        innerConcat[x] = *(reinterpret_cast<uint32_t*>(&ipadKey) + x);
    }
    #pragma unroll
    for (int x = 0; x < 36 / 4; x++)
    {
        innerConcat[128 / 4 + x] = message[x];
    }
    *(reinterpret_cast<uint8_t*>(&innerConcat) + 128 + (37 - 1)) = *const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(message) + 36);

    sha512(reinterpret_cast<uint64_t*>(&innerConcat), 128 + 37, reinterpret_cast<uint64_t*>(output));

    #pragma unroll
    for (int x = 0; x < (128 / 4); x++)
    {
        *(reinterpret_cast<uint32_t*>(&innerConcat) + x) = *(reinterpret_cast<uint32_t*>(&opadKey) + x);
    }
    #pragma unroll
    for (int x = 0; x < (64 / 4); x++)
    {
        *(reinterpret_cast<uint32_t*>(&innerConcat) + 128 / 4 + x) = *(output + x);
    }

    sha512(reinterpret_cast<uint64_t*>(&innerConcat), 192, reinterpret_cast<uint64_t*>(output));
}
