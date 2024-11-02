#include "sha.cuh"
#include "sha_defines.cuh"
#include "sha_constants.cuh"

__device__ uint32_t SWAP256(uint32_t val)
{
    return (rotl32(((val) & (uint32_t) 0x00FF00FF), (uint32_t) 24U) | rotl32(((val) & (uint32_t) 0xFF00FF00), (uint32_t) 8U));
}

__device__ uint64_t SWAP512(uint64_t val)
{
    uint64_t tmp = (rotr64((uint64_t) ((val) & (uint64_t) 0x0000FFFF0000FFFFUL), 16) | rotl64((uint64_t) ((val) & (uint64_t) 0xFFFF0000FFFF0000UL), 16));
    return (rotr64((uint64_t) ((tmp) & (uint64_t) 0xFF00FF00FF00FF00UL), 8) | rotl64((uint64_t) ((tmp) & (uint64_t) 0x00FF00FF00FF00FFUL), 8));
}

__device__ void sha256Process(const uint32_t* W, uint32_t* digest)
{
    uint32_t a = digest[0];
    uint32_t b = digest[1];
    uint32_t c = digest[2];
    uint32_t d = digest[3];
    uint32_t e = digest[4];
    uint32_t f = digest[5];
    uint32_t g = digest[6];
    uint32_t h = digest[7];

    uint32_t w0_t = W[0];
    uint32_t w1_t = W[1];
    uint32_t w2_t = W[2];
    uint32_t w3_t = W[3];
    uint32_t w4_t = W[4];
    uint32_t w5_t = W[5];
    uint32_t w6_t = W[6];
    uint32_t w7_t = W[7];
    uint32_t w8_t = W[8];
    uint32_t w9_t = W[9];
    uint32_t wa_t = W[10];
    uint32_t wb_t = W[11];
    uint32_t wc_t = W[12];
    uint32_t wd_t = W[13];
    uint32_t we_t = W[14];
    uint32_t wf_t = W[15];

    ROUND_STEP(0)
    ROUND_EXPAND()
    ROUND_STEP(16)
    ROUND_EXPAND()
    ROUND_STEP(32)
    ROUND_EXPAND()
    ROUND_STEP(48)

    digest[0] += a;
    digest[1] += b;
    digest[2] += c;
    digest[3] += d;
    digest[4] += e;
    digest[5] += f;
    digest[6] += g;
    digest[7] += h;
}

__device__ void sha256(const uint32_t* pass, int pass_len, uint32_t* hash)
{
    int plen = pass_len / 4;
    if (mod(pass_len, 4)) { plen++; }

    uint32_t* p = hash;
    uint32_t W[0x10];

    int loops = plen;
    int curLoop = 0;

    uint32_t State[8];
    State[0] = 0x6a09e667;
    State[1] = 0xbb67ae85;
    State[2] = 0x3c6ef372;
    State[3] = 0xa54ff53a;
    State[4] = 0x510e527f;
    State[5] = 0x9b05688c;
    State[6] = 0x1f83d9ab;
    State[7] = 0x5be0cd19;
    while (loops > 0)
    {
        W[0x0] = 0x0;
        W[0x1] = 0x0;
        W[0x2] = 0x0;
        W[0x3] = 0x0;
        W[0x4] = 0x0;
        W[0x5] = 0x0;
        W[0x6] = 0x0;
        W[0x7] = 0x0;
        W[0x8] = 0x0;
        W[0x9] = 0x0;
        W[0xA] = 0x0;
        W[0xB] = 0x0;
        W[0xC] = 0x0;
        W[0xD] = 0x0;
        W[0xE] = 0x0;
        W[0xF] = 0x0;
        for (int m = 0; loops != 0 && m < 16; m++)
        {
            W[m] ^= SWAP256(pass[m + (curLoop * 16)]);
            loops--;
        }
        if (loops == 0 && mod(pass_len, 64) != 0)
        {
            uint32_t padding = 0x80 << (((pass_len + 4) - ((pass_len + 4) / 4 * 4)) * 8);
            int v = mod(pass_len, 64);
            W[v / 4] |= SWAP256(padding);
            if ((pass_len & 0x3B) != 0x3B)
            {
                W[0x0F] = pass_len * 8;
            }
        }
        sha256Process(W, State);
        curLoop++;
    }
    if (mod(plen, 16) == 0)
    {
        W[0x0] = 0x0;
        W[0x1] = 0x0;
        W[0x2] = 0x0;
        W[0x3] = 0x0;
        W[0x4] = 0x0;
        W[0x5] = 0x0;
        W[0x6] = 0x0;
        W[0x7] = 0x0;
        W[0x8] = 0x0;
        W[0x9] = 0x0;
        W[0xA] = 0x0;
        W[0xB] = 0x0;
        W[0xC] = 0x0;
        W[0xD] = 0x0;
        W[0xE] = 0x0;
        W[0xF] = 0x0;
        if ((pass_len & 0x3B) != 0x3B)
        {
            uint32_t padding = 0x80 << (((pass_len + 4) - ((pass_len + 4) / 4 * 4)) * 8);
            W[0] |= SWAP256(padding);
        }
        W[0x0F] = pass_len * 8;
        sha256Process(W, State);
    }
    p[0] = SWAP256(State[0]);
    p[1] = SWAP256(State[1]);
    p[2] = SWAP256(State[2]);
    p[3] = SWAP256(State[3]);
    p[4] = SWAP256(State[4]);
    p[5] = SWAP256(State[5]);
    p[6] = SWAP256(State[6]);
    p[7] = SWAP256(State[7]);
}

// 512 bytes
__constant__ constexpr uint64_t padLong[8] = {highBit(0), highBit(1), highBit(2), highBit(3), highBit(4), highBit(5), highBit(6), highBit(7)};

// 512 bytes
__constant__ constexpr uint64_t maskLong[8] = {0, fBytes(1), fBytes(2), fBytes(3), fBytes(4), fBytes(5), fBytes(6), fBytes(7)};

// 1, 383 0's, 128 bit length BE
// uint64_t is 64 bits => 8 bytes so msg[0] is bytes 1->8  msg[1] is bytes 9->16
// msg[24] is bytes 193->200 but our message is only 192 bytes
__device__ void md_pad_128(uint64_t* msg, const long msgLen_bytes)
{
    uint32_t padLongIndex, overhang;
    padLongIndex = ((uint32_t) msgLen_bytes) / 8; // 24
    overhang = (((uint32_t) msgLen_bytes) - padLongIndex * 8); // 0
    msg[padLongIndex] &= maskLong[overhang]; // msg[24] = msg[24] & 0 -> 0's out this byte
    msg[padLongIndex] |= padLong[overhang]; // msg[24] = msg[24] | 0x1UL << 7 -> sets it to 0x1UL << 7
    msg[padLongIndex + 1] = 0; // msg[25] = 0
    msg[padLongIndex + 2] = 0; // msg[26] = 0
    uint32_t i = 0;

    // 27, 28, 29, 30, 31 = 0
    for (i = padLongIndex + 3; i < 32; i++)
    {
        msg[i] = 0;
    }

    msg[i - 2] = 0; // msg[30] = 0; already did this in loop..
    msg[i - 1] = SWAP512(msgLen_bytes * 8); // msg[31] = SWAP512(1536)
}

__device__ void sha512(uint64_t* input, const uint32_t length, uint64_t* hash)
{
    md_pad_128(input, length);
    uint64_t W[80]{};
    uint64_t State[8]{};

    State[0] = 0x6a09e667f3bcc908UL;
    State[1] = 0xbb67ae8584caa73bUL;
    State[2] = 0x3c6ef372fe94f82bUL;
    State[3] = 0xa54ff53a5f1d36f1UL;
    State[4] = 0x510e527fade682d1UL;
    State[5] = 0x9b05688c2b3e6c1fUL;
    State[6] = 0x1f83d9abfb41bd6bUL;
    State[7] = 0x5be0cd19137e2179UL;

    uint64_t a, b, c, d, e, f, g, h;
    for (int block_i = 0; block_i < 2; block_i++)
    {
        W[0] = SWAP512(input[0]);
        W[1] = SWAP512(input[1]);
        W[2] = SWAP512(input[2]);
        W[3] = SWAP512(input[3]);
        W[4] = SWAP512(input[4]);
        W[5] = SWAP512(input[5]);
        W[6] = SWAP512(input[6]);
        W[7] = SWAP512(input[7]);
        W[8] = SWAP512(input[8]);
        W[9] = SWAP512(input[9]);
        W[10] = SWAP512(input[10]);
        W[11] = SWAP512(input[11]);
        W[12] = SWAP512(input[12]);
        W[13] = SWAP512(input[13]);
        W[14] = SWAP512(input[14]);
        W[15] = SWAP512(input[15]);

        //SWAP512_16D(input, W);

        for (int i = 16; i < 80; i++)
        {
            W[i] = W[i - 16] + little_s0(W[i - 15]) + W[i - 7] + little_s1(W[i - 2]);
        }
        a = State[0];
        b = State[1];
        c = State[2];
        d = State[3];
        e = State[4];
        f = State[5];
        g = State[6];
        h = State[7];
        for (int i = 0; i < 80; i += 16)
        {
            ROUND_STEP_SHA512(i)
        }
        State[0] += a;
        State[1] += b;
        State[2] += c;
        State[3] += d;
        State[4] += e;
        State[5] += f;
        State[6] += g;
        State[7] += h;
        input += 16;
    }
    hash[0] = SWAP512(State[0]);
    hash[1] = SWAP512(State[1]);
    hash[2] = SWAP512(State[2]);
    hash[3] = SWAP512(State[3]);
    hash[4] = SWAP512(State[4]);
    hash[5] = SWAP512(State[5]);
    hash[6] = SWAP512(State[6]);
    hash[7] = SWAP512(State[7]);
}

__device__ void md_pad_128_swap(uint64_t* msg, const long msgLen_bytes)
{
    uint32_t padLongIndex, overhang;
    padLongIndex = ((uint32_t) msgLen_bytes) / 8; // 24
    overhang = (((uint32_t) msgLen_bytes) - padLongIndex * 8); // 0
    msg[padLongIndex] &= SWAP512(maskLong[overhang]); // msg[24] = msg[24] & 0 -> 0's out this byte
    msg[padLongIndex] |= SWAP512(padLong[overhang]); // msg[24] = msg[24] | 0x1UL << 7 -> sets it to 0x1UL << 7
    msg[padLongIndex + 1] = 0; // msg[25] = 0
    msg[padLongIndex + 2] = 0; // msg[26] = 0

    uint32_t i = 0;
    // 27, 28, 29, 30, 31 = 0
    for (i = padLongIndex + 3; i < 32; i++)
    {
        msg[i] = 0;
    }

    msg[i - 2] = 0; // msg[30] = 0; already did this in loop..
    msg[i - 1] = msgLen_bytes * 8; // msg[31] = SWAP512(1536)
}

__device__ void sha512_swap(uint64_t* input, const uint32_t length, uint64_t* hash)
{
    md_pad_128_swap(input, length);

    uint64_t W[80]{};
    uint64_t State[8]{};

    State[0] = 0x6a09e667f3bcc908UL;
    State[1] = 0xbb67ae8584caa73bUL;
    State[2] = 0x3c6ef372fe94f82bUL;
    State[3] = 0xa54ff53a5f1d36f1UL;
    State[4] = 0x510e527fade682d1UL;
    State[5] = 0x9b05688c2b3e6c1fUL;
    State[6] = 0x1f83d9abfb41bd6bUL;
    State[7] = 0x5be0cd19137e2179UL;

    uint64_t a, b, c, d, e, f, g, h;
    for (int block_i = 0; block_i < 2; block_i++)
    {
        W[0] = input[0];
        W[1] = input[1];
        W[2] = input[2];
        W[3] = input[3];
        W[4] = input[4];
        W[5] = input[5];
        W[6] = input[6];
        W[7] = input[7];
        W[8] = input[8];
        W[9] = input[9];
        W[10] = input[10];
        W[11] = input[11];
        W[12] = input[12];
        W[13] = input[13];
        W[14] = input[14];
        W[15] = input[15];

        //SWAP512_16D(input, W);
#pragma unroll
        for (int i = 16; i < 80; i++)
        {
            W[i] = W[i - 16] + little_s0(W[i - 15]) + W[i - 7] + little_s1(W[i - 2]);
        }
        a = State[0];
        b = State[1];
        c = State[2];
        d = State[3];
        e = State[4];
        f = State[5];
        g = State[6];
        h = State[7];
#pragma unroll
        for (int i = 0; i < 80; i += 16)
        {
            ROUND_STEP_SHA512(i)
        }
        State[0] += a;
        State[1] += b;
        State[2] += c;
        State[3] += d;
        State[4] += e;
        State[5] += f;
        State[6] += g;
        State[7] += h;
        input += 16;
    }
    hash[0] = State[0];
    hash[1] = State[1];
    hash[2] = State[2];
    hash[3] = State[3];
    hash[4] = State[4];
    hash[5] = State[5];
    hash[6] = State[6];
    hash[7] = State[7];
}
