#pragma once
#include <cstdint>

namespace crypto
{
    class rng
    {
        uint32_t _state[16]{};
        uint32_t _counter{};

        void reseed();

    public:
        rng();

        void get(unsigned char *buf, int len);
    };

    void ripemd160(uint32_t *msg, uint32_t *digest);
    void sha256Init(uint32_t *digest);
    void sha256(uint32_t *msg, uint32_t *digest);
    uint32_t checksum(const uint32_t *hash);
}
