#include "hmac.cuh"
#include "sha.cuh"

__device__ void hmacSHA512(const uint32_t* key, const uint32_t* message, uint32_t* output)
{
    uint32_t ipadKey[128 / 4]{};
    uint32_t opadKey[128 / 4]{};

    for (int x = 0; x < 32 / 4; x++)
    {
        ipadKey[x] = 0x36363636 ^ *(uint32_t*) ((uint32_t*) key + x);
        opadKey[x] = 0x5C5C5C5C ^ *(uint32_t*) ((uint32_t*) key + x);
    }

    for (int x = 32 / 4; x < 128 / 4; x++)
    {
        ipadKey[x] = 0x36363636;
        opadKey[x] = 0x5C5C5C5C;
    }

    uint32_t innerConcat[256 / 4]{};

    for (int x = 0; x < 128 / 4; x++)
    {
        innerConcat[x] = *(uint32_t*) ((uint32_t*) &ipadKey + x);
    }
    for (int x = 0; x < 36 / 4; x++)
    {
        innerConcat[128 / 4 + x] = message[x];
    }
    *(uint8_t*) ((uint8_t*) &innerConcat + 128 + (37 - 1)) = *(uint8_t*) ((uint8_t*) message + 36);

    sha512((uint64_t*) &innerConcat, 128 + 37, (uint64_t*) output);

    for (int x = 0; x < (128 / 4); x++)
    {
        *(uint32_t*) ((uint32_t*) &innerConcat + x) = *(uint32_t*) ((uint32_t*) &opadKey + x);
    }
    for (int x = 0; x < (64 / 4); x++)
    {
        *(uint32_t*) ((uint32_t*) &innerConcat + 128 / 4 + x) = *(uint32_t*) ((uint32_t*) output + x);
    }

    sha512((uint64_t*) &innerConcat, 192, (uint64_t*) output);
}
