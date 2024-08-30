#include "crypto_util.h"

static const uint32_t _K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static const uint32_t _IV[8] = {
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19
};

static uint32_t rotr(uint32_t x, int n)
{
    return (x >> n) | (x << (32 - n));
}

static uint32_t MAJ(uint32_t a, uint32_t b, uint32_t c)
{
    return (a & b) ^ (a & c) ^ (b & c);
}

static uint32_t CH(uint32_t e, uint32_t f, uint32_t g)
{
    return (e & f) ^ (~e & g);
}


static void round(uint32_t a, uint32_t b, uint32_t c, uint32_t &d, unsigned e, uint32_t f, uint32_t g, uint32_t &h, uint32_t m, uint32_t k)
{
    uint32_t s = CH(e, f, g) + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + k + m;

    d += s + h;

    h += s + MAJ(a, b, c) + (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22));
}


void crypto::sha256Init(uint32_t *digest)
{
    for(int i = 0; i < 8; i++) {
        digest[i] = _IV[i];
    }
}

void crypto::sha256(uint32_t *msg, uint32_t *digest)
{
    uint32_t s0, s1;

    uint32_t a = digest[0];
    uint32_t b = digest[1];
    uint32_t c = digest[2];
    uint32_t d = digest[3];
    uint32_t e = digest[4];
    uint32_t f = digest[5];
    uint32_t g = digest[6];
    uint32_t h = digest[7];

    uint32_t w[80]{};
    for(int i = 0; i < 16; i++) {
        w[i] = msg[i];
    }

    // Expand 16 words to 64 words
    for(int i = 16; i < 64; i++)
    {
        uint32_t x = w[i - 15];
        uint32_t y = w[i - 2];

        s0 = rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
        s1 = rotr(y, 17) ^ rotr(y, 19) ^ (y >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    for(int i = 0; i < 64; i += 8) {
        round(a, b, c, d, e, f, g, h, w[i], _K[i]);
        round(h, a, b, c, d, e, f, g, w[i + 1], _K[i + 1]);
        round(g, h, a, b, c, d, e, f, w[i + 2], _K[i + 2]);
        round(f, g, h, a, b, c, d, e, w[i + 3], _K[i + 3]);
        round(e, f, g, h, a, b, c, d, w[i + 4], _K[i + 4]);
        round(d, e, f, g, h, a, b, c, w[i + 5], _K[i + 5]);
        round(c, d, e, f, g, h, a, b, w[i + 6], _K[i + 6]);
        round(b, c, d, e, f, g, h, a, w[i + 7], _K[i + 7]);
    }

    digest[0] += a;
    digest[1] += b;
    digest[2] += c;
    digest[3] += d;
    digest[4] += e;
    digest[5] += f;
    digest[6] += g;
    digest[7] += h;
}