#include "crypto_util.h"

#include <cstring>

#ifdef _WIN32
    #pragma comment(lib, "bcrypt.lib")

    #include <Windows.h>
    #include <bcrypt.h>

    static void secureRandom(uint8_t *buf, uint32_t count)
    {
        BCRYPT_ALG_HANDLE h;
        BCryptOpenAlgorithmProvider(&h, BCRYPT_RNG_ALGORITHM, nullptr, 0);
        BCryptGenRandom(h, buf, count, 0);
    }
#else
    #include <cstdio>
    #include <stdexcept>
    #include <string>

    static void secureRandom(uint8_t *buf, const uint32_t count)
    {
        // Read from /dev/urandom
        FILE *fp = fopen("/dev/urandom", "rb");
        if (fp == nullptr)
        {
            throw std::runtime_error("Fatal error: Cannot open /dev/urandom for reading");
        }
        if (fread(buf, 1, count, fp) != count)
        {
            throw std::runtime_error("Fatal error: Not enough entropy available in /dev/urandom");
        }
        fclose(fp);
    }
#endif


crypto::rng::rng()
{
    reseed();
}

void crypto::rng::reseed()
{
    _counter = 0;
    memset(_state, 0, sizeof(_state));
    secureRandom(reinterpret_cast<uint8_t *>(_state), 32);
}

void crypto::rng::get(uint8_t *buf, int len)
{
    int i = 0;
    while (len > 0)
    {
        if (_counter++ == 0xffffffff)
        {
            reseed();
        }
        _state[15] = _counter;

        uint32_t digest[8]{};
        sha256Init(digest);

        sha256(_state, digest);
        if (len >= 32)
        {
            memcpy(&buf[i], digest, 32);
            i += 32;
            len -= 32;
        }
        else
        {
            memcpy(&buf[i], digest, len);
            i += len;
            len -= len;
        }
    }
}
