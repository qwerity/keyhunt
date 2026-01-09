#pragma once

#include <cuda_runtime.h>
#include "defines.cuh"

constexpr uint32_t d_SHA256_K0{0x428a2f98};
constexpr uint32_t d_SHA256_K1{0x71374491};
constexpr uint32_t d_SHA256_K2{0xb5c0fbcf};
constexpr uint32_t d_SHA256_K3{0xe9b5dba5};
constexpr uint32_t d_SHA256_K4{0x3956c25b};
constexpr uint32_t d_SHA256_K5{0x59f111f1};
constexpr uint32_t d_SHA256_K6{0x923f82a4};
constexpr uint32_t d_SHA256_K7{0xab1c5ed5};
constexpr uint32_t d_SHA256_K8{0xd807aa98};
constexpr uint32_t d_SHA256_K9{0x12835b01};
constexpr uint32_t d_SHA256_K10{0x243185be};
constexpr uint32_t d_SHA256_K11{0x550c7dc3};
constexpr uint32_t d_SHA256_K12{0x72be5d74};
constexpr uint32_t d_SHA256_K13{0x80deb1fe};
constexpr uint32_t d_SHA256_K14{0x9bdc06a7};
constexpr uint32_t d_SHA256_K15{0xc19bf174};
constexpr uint32_t d_SHA256_K16{0xe49b69c1};
constexpr uint32_t d_SHA256_K17{0xefbe4786};
constexpr uint32_t d_SHA256_K18{0x0fc19dc6};
constexpr uint32_t d_SHA256_K19{0x240ca1cc};
constexpr uint32_t d_SHA256_K20{0x2de92c6f};
constexpr uint32_t d_SHA256_K21{0x4a7484aa};
constexpr uint32_t d_SHA256_K22{0x5cb0a9dc};
constexpr uint32_t d_SHA256_K23{0x76f988da};
constexpr uint32_t d_SHA256_K24{0x983e5152};
constexpr uint32_t d_SHA256_K25{0xa831c66d};
constexpr uint32_t d_SHA256_K26{0xb00327c8};
constexpr uint32_t d_SHA256_K27{0xbf597fc7};
constexpr uint32_t d_SHA256_K28{0xc6e00bf3};
constexpr uint32_t d_SHA256_K29{0xd5a79147};
constexpr uint32_t d_SHA256_K30{0x06ca6351};
constexpr uint32_t d_SHA256_K31{0x14292967};
constexpr uint32_t d_SHA256_K32{0x27b70a85};
constexpr uint32_t d_SHA256_K33{0x2e1b2138};
constexpr uint32_t d_SHA256_K34{0x4d2c6dfc};
constexpr uint32_t d_SHA256_K35{0x53380d13};
constexpr uint32_t d_SHA256_K36{0x650a7354};
constexpr uint32_t d_SHA256_K37{0x766a0abb};
constexpr uint32_t d_SHA256_K38{0x81c2c92e};
constexpr uint32_t d_SHA256_K39{0x92722c85};
constexpr uint32_t d_SHA256_K40{0xa2bfe8a1};
constexpr uint32_t d_SHA256_K41{0xa81a664b};
constexpr uint32_t d_SHA256_K42{0xc24b8b70};
constexpr uint32_t d_SHA256_K43{0xc76c51a3};
constexpr uint32_t d_SHA256_K44{0xd192e819};
constexpr uint32_t d_SHA256_K45{0xd6990624};
constexpr uint32_t d_SHA256_K46{0xf40e3585};
constexpr uint32_t d_SHA256_K47{0x106aa070};
constexpr uint32_t d_SHA256_K48{0x19a4c116};
constexpr uint32_t d_SHA256_K49{0x1e376c08};
constexpr uint32_t d_SHA256_K50{0x2748774c};
constexpr uint32_t d_SHA256_K51{0x34b0bcb5};
constexpr uint32_t d_SHA256_K52{0x391c0cb3};
constexpr uint32_t d_SHA256_K53{0x4ed8aa4a};
constexpr uint32_t d_SHA256_K54{0x5b9cca4f};
constexpr uint32_t d_SHA256_K55{0x682e6ff3};
constexpr uint32_t d_SHA256_K56{0x748f82ee};
constexpr uint32_t d_SHA256_K57{0x78a5636f};
constexpr uint32_t d_SHA256_K58{0x84c87814};
constexpr uint32_t d_SHA256_K59{0x8cc70208};
constexpr uint32_t d_SHA256_K60{0x90befffa};
constexpr uint32_t d_SHA256_K61{0xa4506ceb};
constexpr uint32_t d_SHA256_K62{0xbef9a3f7};
constexpr uint32_t d_SHA256_K63{0xc67178f2};

constexpr uint32_t d_IV0{0x6a09e667};
constexpr uint32_t d_IV1{0xbb67ae85};
constexpr uint32_t d_IV2{0x3c6ef372};
constexpr uint32_t d_IV3{0xa54ff53a};
constexpr uint32_t d_IV4{0x510e527f};
constexpr uint32_t d_IV5{0x9b05688c};
constexpr uint32_t d_IV6{0x1f83d9ab};
constexpr uint32_t d_IV7{0x5be0cd19};


__device__ __forceinline__ uint32_t rotr(const uint32_t x, const int n)
{
    return (x >> n) ^ (x << (32 - n));
}

__device__ __forceinline__ uint32_t MAJ(const uint32_t a, const uint32_t b, const uint32_t c)
{
    return (a & b) ^ (a & c) ^ (b & c);
}

__device__ __forceinline__ uint32_t CH(const uint32_t e, const uint32_t f, const uint32_t g)
{
    return (e & f) ^ (~e & g);
}

__device__ __forceinline__ uint32_t s0(const uint32_t x)
{
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

__device__ __forceinline__ uint32_t s1(const uint32_t x)
{
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}


__device__ __forceinline__ void roundSha256(const uint32_t a, const uint32_t b, const uint32_t c, uint32_t &d, const uint32_t e, const uint32_t f, const uint32_t g, uint32_t &h, const uint32_t m, const uint32_t k)
{
    const uint32_t s = CH(e, f, g) + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + k + m;

    d += s + h;

    h += s + MAJ(a, b, c) + (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22));
}

__device__ __forceinline__ void sha256PublicKey(const uint256_t& x, const uint256_t& y, uint256_t& digest)
{
    uint32_t w[16];

    // 0x04 || x || y
    // После исправления secp256k1_bytes_to_uint256_optimized:
    // x.v[7] содержит старшие 32 бита (big-endian внутри слова) = x[0] в CPU после exportWords
    // x.v[0] содержит младшие 32 бита (big-endian внутри слова) = x[7] в CPU после exportWords
    // В CPU версии msg заполняется в обратном порядке, но SHA256 обрабатывает от msg[0] до msg[15]
    // Поэтому нужно использовать прямой порядок индексов в CUDA
    // CPU: msg[0] = (x[0] >> 8) | 0x04000000, где x[0] = v[7] (старшие)
    // CUDA: w[0] = (x.v[7] >> 8) | 0x04000000 - правильно
    w[0] = (x.v[7] >> 8) | 0x04000000;
    w[1] = (x.v[6] >> 8) | (x.v[7] << 24);
    w[2] = (x.v[5] >> 8) | (x.v[6] << 24);
    w[3] = (x.v[4] >> 8) | (x.v[5] << 24);
    w[4] = (x.v[3] >> 8) | (x.v[4] << 24);
    w[5] = (x.v[2] >> 8) | (x.v[3] << 24);
    w[6] = (x.v[1] >> 8) | (x.v[2] << 24);
    w[7] = (x.v[0] >> 8) | (x.v[1] << 24);
    // В CPU версии: msg[8] = (y[0] >> 8) | (x[7] << 24), где y[0] = v[7] (старшие), x[7] = v[0] (младшие)
    // В CUDA версии: y.v[7] = старшие, x.v[0] = младшие
    w[8] = (y.v[7] >> 8) | (x.v[0] << 24);
    // В CPU версии: msg[9] = (y[1] >> 8) | (y[0] << 24), где y[1] = v[6], y[0] = v[7]
    // В CUDA версии: y.v[6], y.v[7]
    w[9] = (y.v[6] >> 8) | (y.v[7] << 24);
    w[10] = (y.v[5] >> 8) | (y.v[6] << 24);
    w[11] = (y.v[4] >> 8) | (y.v[5] << 24);
    w[12] = (y.v[3] >> 8) | (y.v[4] << 24);
    w[13] = (y.v[2] >> 8) | (y.v[3] << 24);
    w[14] = (y.v[1] >> 8) | (y.v[2] << 24);
    // В CPU версии: msg[15] = (y[7] >> 8) | (y[6] << 24), где y[7] = v[0] (младшие), y[6] = v[1]
    // В CUDA версии: y.v[0] = младшие, y.v[1]
    w[15] = (y.v[0] >> 8) | (y.v[1] << 24);

    uint32_t a{d_IV0};
    uint32_t b{d_IV1};
    uint32_t c{d_IV2};
    uint32_t d{d_IV3};
    uint32_t e{d_IV4};
    uint32_t f{d_IV5};
    uint32_t g{d_IV6};
    uint32_t h{d_IV7};

    roundSha256(a, b, c, d, e, f, g, h, w[0], d_SHA256_K0);
    roundSha256(h, a, b, c, d, e, f, g, w[1], d_SHA256_K1);
    roundSha256(g, h, a, b, c, d, e, f, w[2], d_SHA256_K2);
    roundSha256(f, g, h, a, b, c, d, e, w[3], d_SHA256_K3);
    roundSha256(e, f, g, h, a, b, c, d, w[4], d_SHA256_K4);
    roundSha256(d, e, f, g, h, a, b, c, w[5], d_SHA256_K5);
    roundSha256(c, d, e, f, g, h, a, b, w[6], d_SHA256_K6);
    roundSha256(b, c, d, e, f, g, h, a, w[7], d_SHA256_K7);
    roundSha256(a, b, c, d, e, f, g, h, w[8], d_SHA256_K8);
    roundSha256(h, a, b, c, d, e, f, g, w[9], d_SHA256_K9);
    roundSha256(g, h, a, b, c, d, e, f, w[10], d_SHA256_K10);
    roundSha256(f, g, h, a, b, c, d, e, w[11], d_SHA256_K11);
    roundSha256(e, f, g, h, a, b, c, d, w[12], d_SHA256_K12);
    roundSha256(d, e, f, g, h, a, b, c, w[13], d_SHA256_K13);
    roundSha256(c, d, e, f, g, h, a, b, w[14], d_SHA256_K14);
    roundSha256(b, c, d, e, f, g, h, a, w[15], d_SHA256_K15);

    w[0] = w[0] + s0(w[1]) + w[9] + s1(w[14]);
    w[1] = w[1] + s0(w[2]) + w[10] + s1(w[15]);
    w[2] = w[2] + s0(w[3]) + w[11] + s1(w[0]);
    w[3] = w[3] + s0(w[4]) + w[12] + s1(w[1]);
    w[4] = w[4] + s0(w[5]) + w[13] + s1(w[2]);
    w[5] = w[5] + s0(w[6]) + w[14] + s1(w[3]);
    w[6] = w[6] + s0(w[7]) + w[15] + s1(w[4]);
    w[7] = w[7] + s0(w[8]) + w[0] + s1(w[5]);
    w[8] = w[8] + s0(w[9]) + w[1] + s1(w[6]);
    w[9] = w[9] + s0(w[10]) + w[2] + s1(w[7]);
    w[10] = w[10] + s0(w[11]) + w[3] + s1(w[8]);
    w[11] = w[11] + s0(w[12]) + w[4] + s1(w[9]);
    w[12] = w[12] + s0(w[13]) + w[5] + s1(w[10]);
    w[13] = w[13] + s0(w[14]) + w[6] + s1(w[11]);
    w[14] = w[14] + s0(w[15]) + w[7] + s1(w[12]);
    w[15] = w[15] + s0(w[0]) + w[8] + s1(w[13]);

    roundSha256(a, b, c, d, e, f, g, h, w[0], d_SHA256_K16);
    roundSha256(h, a, b, c, d, e, f, g, w[1], d_SHA256_K17);
    roundSha256(g, h, a, b, c, d, e, f, w[2], d_SHA256_K18);
    roundSha256(f, g, h, a, b, c, d, e, w[3], d_SHA256_K19);
    roundSha256(e, f, g, h, a, b, c, d, w[4], d_SHA256_K20);
    roundSha256(d, e, f, g, h, a, b, c, w[5], d_SHA256_K21);
    roundSha256(c, d, e, f, g, h, a, b, w[6], d_SHA256_K22);
    roundSha256(b, c, d, e, f, g, h, a, w[7], d_SHA256_K23);
    roundSha256(a, b, c, d, e, f, g, h, w[8], d_SHA256_K24);
    roundSha256(h, a, b, c, d, e, f, g, w[9], d_SHA256_K25);
    roundSha256(g, h, a, b, c, d, e, f, w[10], d_SHA256_K26);
    roundSha256(f, g, h, a, b, c, d, e, w[11], d_SHA256_K27);
    roundSha256(e, f, g, h, a, b, c, d, w[12], d_SHA256_K28);
    roundSha256(d, e, f, g, h, a, b, c, w[13], d_SHA256_K29);
    roundSha256(c, d, e, f, g, h, a, b, w[14], d_SHA256_K30);
    roundSha256(b, c, d, e, f, g, h, a, w[15], d_SHA256_K31);

    w[0] = w[0] + s0(w[1]) + w[9] + s1(w[14]);
    w[1] = w[1] + s0(w[2]) + w[10] + s1(w[15]);
    w[2] = w[2] + s0(w[3]) + w[11] + s1(w[0]);
    w[3] = w[3] + s0(w[4]) + w[12] + s1(w[1]);
    w[4] = w[4] + s0(w[5]) + w[13] + s1(w[2]);
    w[5] = w[5] + s0(w[6]) + w[14] + s1(w[3]);
    w[6] = w[6] + s0(w[7]) + w[15] + s1(w[4]);
    w[7] = w[7] + s0(w[8]) + w[0] + s1(w[5]);
    w[8] = w[8] + s0(w[9]) + w[1] + s1(w[6]);
    w[9] = w[9] + s0(w[10]) + w[2] + s1(w[7]);
    w[10] = w[10] + s0(w[11]) + w[3] + s1(w[8]);
    w[11] = w[11] + s0(w[12]) + w[4] + s1(w[9]);
    w[12] = w[12] + s0(w[13]) + w[5] + s1(w[10]);
    w[13] = w[13] + s0(w[14]) + w[6] + s1(w[11]);
    w[14] = w[14] + s0(w[15]) + w[7] + s1(w[12]);
    w[15] = w[15] + s0(w[0]) + w[8] + s1(w[13]);

    roundSha256(a, b, c, d, e, f, g, h, w[0], d_SHA256_K32);
    roundSha256(h, a, b, c, d, e, f, g, w[1], d_SHA256_K33);
    roundSha256(g, h, a, b, c, d, e, f, w[2], d_SHA256_K34);
    roundSha256(f, g, h, a, b, c, d, e, w[3], d_SHA256_K35);
    roundSha256(e, f, g, h, a, b, c, d, w[4], d_SHA256_K36);
    roundSha256(d, e, f, g, h, a, b, c, w[5], d_SHA256_K37);
    roundSha256(c, d, e, f, g, h, a, b, w[6], d_SHA256_K38);
    roundSha256(b, c, d, e, f, g, h, a, w[7], d_SHA256_K39);
    roundSha256(a, b, c, d, e, f, g, h, w[8], d_SHA256_K40);
    roundSha256(h, a, b, c, d, e, f, g, w[9], d_SHA256_K41);
    roundSha256(g, h, a, b, c, d, e, f, w[10], d_SHA256_K42);
    roundSha256(f, g, h, a, b, c, d, e, w[11], d_SHA256_K43);
    roundSha256(e, f, g, h, a, b, c, d, w[12], d_SHA256_K44);
    roundSha256(d, e, f, g, h, a, b, c, w[13], d_SHA256_K45);
    roundSha256(c, d, e, f, g, h, a, b, w[14], d_SHA256_K46);
    roundSha256(b, c, d, e, f, g, h, a, w[15], d_SHA256_K47);

    w[0] = w[0] + s0(w[1]) + w[9] + s1(w[14]);
    w[1] = w[1] + s0(w[2]) + w[10] + s1(w[15]);
    w[2] = w[2] + s0(w[3]) + w[11] + s1(w[0]);
    w[3] = w[3] + s0(w[4]) + w[12] + s1(w[1]);
    w[4] = w[4] + s0(w[5]) + w[13] + s1(w[2]);
    w[5] = w[5] + s0(w[6]) + w[14] + s1(w[3]);
    w[6] = w[6] + s0(w[7]) + w[15] + s1(w[4]);
    w[7] = w[7] + s0(w[8]) + w[0] + s1(w[5]);
    w[8] = w[8] + s0(w[9]) + w[1] + s1(w[6]);
    w[9] = w[9] + s0(w[10]) + w[2] + s1(w[7]);
    w[10] = w[10] + s0(w[11]) + w[3] + s1(w[8]);
    w[11] = w[11] + s0(w[12]) + w[4] + s1(w[9]);
    w[12] = w[12] + s0(w[13]) + w[5] + s1(w[10]);
    w[13] = w[13] + s0(w[14]) + w[6] + s1(w[11]);
    w[14] = w[14] + s0(w[15]) + w[7] + s1(w[12]);
    w[15] = w[15] + s0(w[0]) + w[8] + s1(w[13]);

    roundSha256(a, b, c, d, e, f, g, h, w[0], d_SHA256_K48);
    roundSha256(h, a, b, c, d, e, f, g, w[1], d_SHA256_K49);
    roundSha256(g, h, a, b, c, d, e, f, w[2], d_SHA256_K50);
    roundSha256(f, g, h, a, b, c, d, e, w[3], d_SHA256_K51);
    roundSha256(e, f, g, h, a, b, c, d, w[4], d_SHA256_K52);
    roundSha256(d, e, f, g, h, a, b, c, w[5], d_SHA256_K53);
    roundSha256(c, d, e, f, g, h, a, b, w[6], d_SHA256_K54);
    roundSha256(b, c, d, e, f, g, h, a, w[7], d_SHA256_K55);
    roundSha256(a, b, c, d, e, f, g, h, w[8], d_SHA256_K56);
    roundSha256(h, a, b, c, d, e, f, g, w[9], d_SHA256_K57);
    roundSha256(g, h, a, b, c, d, e, f, w[10], d_SHA256_K58);
    roundSha256(f, g, h, a, b, c, d, e, w[11], d_SHA256_K59);
    roundSha256(e, f, g, h, a, b, c, d, w[12], d_SHA256_K60);
    roundSha256(d, e, f, g, h, a, b, c, w[13], d_SHA256_K61);
    roundSha256(c, d, e, f, g, h, a, b, w[14], d_SHA256_K62);
    roundSha256(b, c, d, e, f, g, h, a, w[15], d_SHA256_K63);

    a += d_IV0;
    b += d_IV1;
    c += d_IV2;
    d += d_IV3;
    e += d_IV4;
    f += d_IV5;
    g += d_IV6;
    h += d_IV7;

    // store the intermediate hash value
    uint32_t tmp[8];
    tmp[0] = a;
    tmp[1] = b;
    tmp[2] = c;
    tmp[3] = d;
    tmp[4] = e;
    tmp[5] = f;
    tmp[6] = g;
    tmp[7] = h;

    // В CPU версии: msg[0] = (y[7] << 24) | 0x00800000, где y[7] это младшие 32 бита (после exportWords)
    // В CUDA версии: y.v[0] содержит младшие 32 бита, поэтому используем y.v[0]
    w[0] = (y.v[0] << 24) | 0x00800000;
    w[15] = 65 * 8;

    roundSha256(a, b, c, d, e, f, g, h, w[0], d_SHA256_K0);
    roundSha256(h, a, b, c, d, e, f, g, 0, d_SHA256_K1);
    roundSha256(g, h, a, b, c, d, e, f, 0, d_SHA256_K2);
    roundSha256(f, g, h, a, b, c, d, e, 0, d_SHA256_K3);
    roundSha256(e, f, g, h, a, b, c, d, 0, d_SHA256_K4);
    roundSha256(d, e, f, g, h, a, b, c, 0, d_SHA256_K5);
    roundSha256(c, d, e, f, g, h, a, b, 0, d_SHA256_K6);
    roundSha256(b, c, d, e, f, g, h, a, 0, d_SHA256_K7);
    roundSha256(a, b, c, d, e, f, g, h, 0, d_SHA256_K8);
    roundSha256(h, a, b, c, d, e, f, g, 0, d_SHA256_K9);
    roundSha256(g, h, a, b, c, d, e, f, 0, d_SHA256_K10);
    roundSha256(f, g, h, a, b, c, d, e, 0, d_SHA256_K11);
    roundSha256(e, f, g, h, a, b, c, d, 0, d_SHA256_K12);
    roundSha256(d, e, f, g, h, a, b, c, 0, d_SHA256_K13);
    roundSha256(c, d, e, f, g, h, a, b, 0, d_SHA256_K14);
    roundSha256(b, c, d, e, f, g, h, a, w[15], d_SHA256_K15);

    w[0] = w[0] + s0(0) + 0 + s1(0);
    w[1] = 0 + s0(0) + 0 + s1(w[15]);
    w[2] = 0 + s0(0) + 0 + s1(w[0]);
    w[3] = 0 + s0(0) + 0 + s1(w[1]);
    w[4] = 0 + s0(0) + 0 + s1(w[2]);
    w[5] = 0 + s0(0) + 0 + s1(w[3]);
    w[6] = 0 + s0(0) + w[15] + s1(w[4]);
    w[7] = 0 + s0(0) + w[0] + s1(w[5]);
    w[8] = 0 + s0(0) + w[1] + s1(w[6]);
    w[9] = 0 + s0(0) + w[2] + s1(w[7]);
    w[10] = 0 + s0(0) + w[3] + s1(w[8]);
    w[11] = 0 + s0(0) + w[4] + s1(w[9]);
    w[12] = 0 + s0(0) + w[5] + s1(w[10]);
    w[13] = 0 + s0(0) + w[6] + s1(w[11]);
    w[14] = 0 + s0(w[15]) + w[7] + s1(w[12]);
    w[15] = w[15] + s0(w[0]) + w[8] + s1(w[13]);

    roundSha256(a, b, c, d, e, f, g, h, w[0], d_SHA256_K16);
    roundSha256(h, a, b, c, d, e, f, g, w[1], d_SHA256_K17);
    roundSha256(g, h, a, b, c, d, e, f, w[2], d_SHA256_K18);
    roundSha256(f, g, h, a, b, c, d, e, w[3], d_SHA256_K19);
    roundSha256(e, f, g, h, a, b, c, d, w[4], d_SHA256_K20);
    roundSha256(d, e, f, g, h, a, b, c, w[5], d_SHA256_K21);
    roundSha256(c, d, e, f, g, h, a, b, w[6], d_SHA256_K22);
    roundSha256(b, c, d, e, f, g, h, a, w[7], d_SHA256_K23);
    roundSha256(a, b, c, d, e, f, g, h, w[8], d_SHA256_K24);
    roundSha256(h, a, b, c, d, e, f, g, w[9], d_SHA256_K25);
    roundSha256(g, h, a, b, c, d, e, f, w[10], d_SHA256_K26);
    roundSha256(f, g, h, a, b, c, d, e, w[11], d_SHA256_K27);
    roundSha256(e, f, g, h, a, b, c, d, w[12], d_SHA256_K28);
    roundSha256(d, e, f, g, h, a, b, c, w[13], d_SHA256_K29);
    roundSha256(c, d, e, f, g, h, a, b, w[14], d_SHA256_K30);
    roundSha256(b, c, d, e, f, g, h, a, w[15], d_SHA256_K31);

    w[0] = w[0] + s0(w[1]) + w[9] + s1(w[14]);
    w[1] = w[1] + s0(w[2]) + w[10] + s1(w[15]);
    w[2] = w[2] + s0(w[3]) + w[11] + s1(w[0]);
    w[3] = w[3] + s0(w[4]) + w[12] + s1(w[1]);
    w[4] = w[4] + s0(w[5]) + w[13] + s1(w[2]);
    w[5] = w[5] + s0(w[6]) + w[14] + s1(w[3]);
    w[6] = w[6] + s0(w[7]) + w[15] + s1(w[4]);
    w[7] = w[7] + s0(w[8]) + w[0] + s1(w[5]);
    w[8] = w[8] + s0(w[9]) + w[1] + s1(w[6]);
    w[9] = w[9] + s0(w[10]) + w[2] + s1(w[7]);
    w[10] = w[10] + s0(w[11]) + w[3] + s1(w[8]);
    w[11] = w[11] + s0(w[12]) + w[4] + s1(w[9]);
    w[12] = w[12] + s0(w[13]) + w[5] + s1(w[10]);
    w[13] = w[13] + s0(w[14]) + w[6] + s1(w[11]);
    w[14] = w[14] + s0(w[15]) + w[7] + s1(w[12]);
    w[15] = w[15] + s0(w[0]) + w[8] + s1(w[13]);

    roundSha256(a, b, c, d, e, f, g, h, w[0], d_SHA256_K32);
    roundSha256(h, a, b, c, d, e, f, g, w[1], d_SHA256_K33);
    roundSha256(g, h, a, b, c, d, e, f, w[2], d_SHA256_K34);
    roundSha256(f, g, h, a, b, c, d, e, w[3], d_SHA256_K35);
    roundSha256(e, f, g, h, a, b, c, d, w[4], d_SHA256_K36);
    roundSha256(d, e, f, g, h, a, b, c, w[5], d_SHA256_K37);
    roundSha256(c, d, e, f, g, h, a, b, w[6], d_SHA256_K38);
    roundSha256(b, c, d, e, f, g, h, a, w[7], d_SHA256_K39);
    roundSha256(a, b, c, d, e, f, g, h, w[8], d_SHA256_K40);
    roundSha256(h, a, b, c, d, e, f, g, w[9], d_SHA256_K41);
    roundSha256(g, h, a, b, c, d, e, f, w[10], d_SHA256_K42);
    roundSha256(f, g, h, a, b, c, d, e, w[11], d_SHA256_K43);
    roundSha256(e, f, g, h, a, b, c, d, w[12], d_SHA256_K44);
    roundSha256(d, e, f, g, h, a, b, c, w[13], d_SHA256_K45);
    roundSha256(c, d, e, f, g, h, a, b, w[14], d_SHA256_K46);
    roundSha256(b, c, d, e, f, g, h, a, w[15], d_SHA256_K47);

    w[0] = w[0] + s0(w[1]) + w[9] + s1(w[14]);
    w[1] = w[1] + s0(w[2]) + w[10] + s1(w[15]);
    w[2] = w[2] + s0(w[3]) + w[11] + s1(w[0]);
    w[3] = w[3] + s0(w[4]) + w[12] + s1(w[1]);
    w[4] = w[4] + s0(w[5]) + w[13] + s1(w[2]);
    w[5] = w[5] + s0(w[6]) + w[14] + s1(w[3]);
    w[6] = w[6] + s0(w[7]) + w[15] + s1(w[4]);
    w[7] = w[7] + s0(w[8]) + w[0] + s1(w[5]);
    w[8] = w[8] + s0(w[9]) + w[1] + s1(w[6]);
    w[9] = w[9] + s0(w[10]) + w[2] + s1(w[7]);
    w[10] = w[10] + s0(w[11]) + w[3] + s1(w[8]);
    w[11] = w[11] + s0(w[12]) + w[4] + s1(w[9]);
    w[12] = w[12] + s0(w[13]) + w[5] + s1(w[10]);
    w[13] = w[13] + s0(w[14]) + w[6] + s1(w[11]);
    w[14] = w[14] + s0(w[15]) + w[7] + s1(w[12]);
    w[15] = w[15] + s0(w[0]) + w[8] + s1(w[13]);

    roundSha256(a, b, c, d, e, f, g, h, w[0], d_SHA256_K48);
    roundSha256(h, a, b, c, d, e, f, g, w[1], d_SHA256_K49);
    roundSha256(g, h, a, b, c, d, e, f, w[2], d_SHA256_K50);
    roundSha256(f, g, h, a, b, c, d, e, w[3], d_SHA256_K51);
    roundSha256(e, f, g, h, a, b, c, d, w[4], d_SHA256_K52);
    roundSha256(d, e, f, g, h, a, b, c, w[5], d_SHA256_K53);
    roundSha256(c, d, e, f, g, h, a, b, w[6], d_SHA256_K54);
    roundSha256(b, c, d, e, f, g, h, a, w[7], d_SHA256_K55);
    roundSha256(a, b, c, d, e, f, g, h, w[8], d_SHA256_K56);
    roundSha256(h, a, b, c, d, e, f, g, w[9], d_SHA256_K57);
    roundSha256(g, h, a, b, c, d, e, f, w[10], d_SHA256_K58);
    roundSha256(f, g, h, a, b, c, d, e, w[11], d_SHA256_K59);
    roundSha256(e, f, g, h, a, b, c, d, w[12], d_SHA256_K60);
    roundSha256(d, e, f, g, h, a, b, c, w[13], d_SHA256_K61);
    roundSha256(c, d, e, f, g, h, a, b, w[14], d_SHA256_K62);
    roundSha256(b, c, d, e, f, g, h, a, w[15], d_SHA256_K63);

    digest[0] = tmp[0] + a;
    digest[1] = tmp[1] + b;
    digest[2] = tmp[2] + c;
    digest[3] = tmp[3] + d;
    digest[4] = tmp[4] + e;
    digest[5] = tmp[5] + f;
    digest[6] = tmp[6] + g;
    digest[7] = tmp[7] + h;
}

__device__ __forceinline__
void sha256PublicKeyCompressed(const uint256_t& x, const uint32_t yParity, uint256_t& digest)
{
    uint32_t w[16];

    // 0x03 || x  or  0x02 || x
    // После исправления secp256k1_bytes_to_uint256_optimized:
    // x.v[7] содержит старшие 32 бита (big-endian внутри слова)
    // x.v[0] содержит младшие 32 бита (big-endian внутри слова)
    // В CPU версии после exportWords с BigEndian: x[0] = v[7] (старшие), x[7] = v[0] (младшие)
    // Для совместимости: используем x.v[7] для старших битов (как x[0] в CPU), x.v[0] для младших (как x[7] в CPU)
    w[0] = 0x02000000 | ((yParity & 1) << 24) | (x.v[7] >> 8);

    w[1] = (x.v[6] >> 8) | (x.v[7] << 24);
    w[2] = (x.v[5] >> 8) | (x.v[6] << 24);
    w[3] = (x.v[4] >> 8) | (x.v[5] << 24);
    w[4] = (x.v[3] >> 8) | (x.v[4] << 24);
    w[5] = (x.v[2] >> 8) | (x.v[3] << 24);
    w[6] = (x.v[1] >> 8) | (x.v[2] << 24);
    w[7] = (x.v[0] >> 8) | (x.v[1] << 24);
    w[8] = (x.v[0] << 24) | 0x00800000;
    w[15] = 33 * 8;

    uint32_t a{d_IV0};
    uint32_t b{d_IV1};
    uint32_t c{d_IV2};
    uint32_t d{d_IV3};
    uint32_t e{d_IV4};
    uint32_t f{d_IV5};
    uint32_t g{d_IV6};
    uint32_t h{d_IV7};

    roundSha256(a, b, c, d, e, f, g, h, w[0], d_SHA256_K0);
    roundSha256(h, a, b, c, d, e, f, g, w[1], d_SHA256_K1);
    roundSha256(g, h, a, b, c, d, e, f, w[2], d_SHA256_K2);
    roundSha256(f, g, h, a, b, c, d, e, w[3], d_SHA256_K3);
    roundSha256(e, f, g, h, a, b, c, d, w[4], d_SHA256_K4);
    roundSha256(d, e, f, g, h, a, b, c, w[5], d_SHA256_K5);
    roundSha256(c, d, e, f, g, h, a, b, w[6], d_SHA256_K6);
    roundSha256(b, c, d, e, f, g, h, a, w[7], d_SHA256_K7);
    roundSha256(a, b, c, d, e, f, g, h, w[8], d_SHA256_K8);
    roundSha256(h, a, b, c, d, e, f, g, 0, d_SHA256_K9);
    roundSha256(g, h, a, b, c, d, e, f, 0, d_SHA256_K10);
    roundSha256(f, g, h, a, b, c, d, e, 0, d_SHA256_K11);
    roundSha256(e, f, g, h, a, b, c, d, 0, d_SHA256_K12);
    roundSha256(d, e, f, g, h, a, b, c, 0, d_SHA256_K13);
    roundSha256(c, d, e, f, g, h, a, b, 0, d_SHA256_K14);
    roundSha256(b, c, d, e, f, g, h, a, w[15], d_SHA256_K15);

    w[0] = w[0] + s0(w[1]) + 0 + s1(0);
    w[1] = w[1] + s0(w[2]) + 0 + s1(w[15]);
    w[2] = w[2] + s0(w[3]) + 0 + s1(w[0]);
    w[3] = w[3] + s0(w[4]) + 0 + s1(w[1]);
    w[4] = w[4] + s0(w[5]) + 0 + s1(w[2]);
    w[5] = w[5] + s0(w[6]) + 0 + s1(w[3]);
    w[6] = w[6] + s0(w[7]) + w[15] + s1(w[4]);
    w[7] = w[7] + s0(w[8]) + w[0] + s1(w[5]);
    w[8] = w[8] + s0(0) + w[1] + s1(w[6]);
    w[9] = 0 + s0(0) + w[2] + s1(w[7]);
    w[10] = 0 + s0(0) + w[3] + s1(w[8]);
    w[11] = 0 + s0(0) + w[4] + s1(w[9]);
    w[12] = 0 + s0(0) + w[5] + s1(w[10]);
    w[13] = 0 + s0(0) + w[6] + s1(w[11]);
    w[14] = 0 + s0(w[15]) + w[7] + s1(w[12]);
    w[15] = w[15] + s0(w[0]) + w[8] + s1(w[13]);

    roundSha256(a, b, c, d, e, f, g, h, w[0], d_SHA256_K16);
    roundSha256(h, a, b, c, d, e, f, g, w[1], d_SHA256_K17);
    roundSha256(g, h, a, b, c, d, e, f, w[2], d_SHA256_K18);
    roundSha256(f, g, h, a, b, c, d, e, w[3], d_SHA256_K19);
    roundSha256(e, f, g, h, a, b, c, d, w[4], d_SHA256_K20);
    roundSha256(d, e, f, g, h, a, b, c, w[5], d_SHA256_K21);
    roundSha256(c, d, e, f, g, h, a, b, w[6], d_SHA256_K22);
    roundSha256(b, c, d, e, f, g, h, a, w[7], d_SHA256_K23);
    roundSha256(a, b, c, d, e, f, g, h, w[8], d_SHA256_K24);
    roundSha256(h, a, b, c, d, e, f, g, w[9], d_SHA256_K25);
    roundSha256(g, h, a, b, c, d, e, f, w[10], d_SHA256_K26);
    roundSha256(f, g, h, a, b, c, d, e, w[11], d_SHA256_K27);
    roundSha256(e, f, g, h, a, b, c, d, w[12], d_SHA256_K28);
    roundSha256(d, e, f, g, h, a, b, c, w[13], d_SHA256_K29);
    roundSha256(c, d, e, f, g, h, a, b, w[14], d_SHA256_K30);
    roundSha256(b, c, d, e, f, g, h, a, w[15], d_SHA256_K31);

    w[0] = w[0] + s0(w[1]) + w[9] + s1(w[14]);
    w[1] = w[1] + s0(w[2]) + w[10] + s1(w[15]);
    w[2] = w[2] + s0(w[3]) + w[11] + s1(w[0]);
    w[3] = w[3] + s0(w[4]) + w[12] + s1(w[1]);
    w[4] = w[4] + s0(w[5]) + w[13] + s1(w[2]);
    w[5] = w[5] + s0(w[6]) + w[14] + s1(w[3]);
    w[6] = w[6] + s0(w[7]) + w[15] + s1(w[4]);
    w[7] = w[7] + s0(w[8]) + w[0] + s1(w[5]);
    w[8] = w[8] + s0(w[9]) + w[1] + s1(w[6]);
    w[9] = w[9] + s0(w[10]) + w[2] + s1(w[7]);
    w[10] = w[10] + s0(w[11]) + w[3] + s1(w[8]);
    w[11] = w[11] + s0(w[12]) + w[4] + s1(w[9]);
    w[12] = w[12] + s0(w[13]) + w[5] + s1(w[10]);
    w[13] = w[13] + s0(w[14]) + w[6] + s1(w[11]);
    w[14] = w[14] + s0(w[15]) + w[7] + s1(w[12]);
    w[15] = w[15] + s0(w[0]) + w[8] + s1(w[13]);

    roundSha256(a, b, c, d, e, f, g, h, w[0], d_SHA256_K32);
    roundSha256(h, a, b, c, d, e, f, g, w[1], d_SHA256_K33);
    roundSha256(g, h, a, b, c, d, e, f, w[2], d_SHA256_K34);
    roundSha256(f, g, h, a, b, c, d, e, w[3], d_SHA256_K35);
    roundSha256(e, f, g, h, a, b, c, d, w[4], d_SHA256_K36);
    roundSha256(d, e, f, g, h, a, b, c, w[5], d_SHA256_K37);
    roundSha256(c, d, e, f, g, h, a, b, w[6], d_SHA256_K38);
    roundSha256(b, c, d, e, f, g, h, a, w[7], d_SHA256_K39);
    roundSha256(a, b, c, d, e, f, g, h, w[8], d_SHA256_K40);
    roundSha256(h, a, b, c, d, e, f, g, w[9], d_SHA256_K41);
    roundSha256(g, h, a, b, c, d, e, f, w[10], d_SHA256_K42);
    roundSha256(f, g, h, a, b, c, d, e, w[11], d_SHA256_K43);
    roundSha256(e, f, g, h, a, b, c, d, w[12], d_SHA256_K44);
    roundSha256(d, e, f, g, h, a, b, c, w[13], d_SHA256_K45);
    roundSha256(c, d, e, f, g, h, a, b, w[14], d_SHA256_K46);
    roundSha256(b, c, d, e, f, g, h, a, w[15], d_SHA256_K47);

    w[0] = w[0] + s0(w[1]) + w[9] + s1(w[14]);
    w[1] = w[1] + s0(w[2]) + w[10] + s1(w[15]);
    w[2] = w[2] + s0(w[3]) + w[11] + s1(w[0]);
    w[3] = w[3] + s0(w[4]) + w[12] + s1(w[1]);
    w[4] = w[4] + s0(w[5]) + w[13] + s1(w[2]);
    w[5] = w[5] + s0(w[6]) + w[14] + s1(w[3]);
    w[6] = w[6] + s0(w[7]) + w[15] + s1(w[4]);
    w[7] = w[7] + s0(w[8]) + w[0] + s1(w[5]);
    w[8] = w[8] + s0(w[9]) + w[1] + s1(w[6]);
    w[9] = w[9] + s0(w[10]) + w[2] + s1(w[7]);
    w[10] = w[10] + s0(w[11]) + w[3] + s1(w[8]);
    w[11] = w[11] + s0(w[12]) + w[4] + s1(w[9]);
    w[12] = w[12] + s0(w[13]) + w[5] + s1(w[10]);
    w[13] = w[13] + s0(w[14]) + w[6] + s1(w[11]);
    w[14] = w[14] + s0(w[15]) + w[7] + s1(w[12]);
    w[15] = w[15] + s0(w[0]) + w[8] + s1(w[13]);

    roundSha256(a, b, c, d, e, f, g, h, w[0], d_SHA256_K48);
    roundSha256(h, a, b, c, d, e, f, g, w[1], d_SHA256_K49);
    roundSha256(g, h, a, b, c, d, e, f, w[2], d_SHA256_K50);
    roundSha256(f, g, h, a, b, c, d, e, w[3], d_SHA256_K51);
    roundSha256(e, f, g, h, a, b, c, d, w[4], d_SHA256_K52);
    roundSha256(d, e, f, g, h, a, b, c, w[5], d_SHA256_K53);
    roundSha256(c, d, e, f, g, h, a, b, w[6], d_SHA256_K54);
    roundSha256(b, c, d, e, f, g, h, a, w[7], d_SHA256_K55);
    roundSha256(a, b, c, d, e, f, g, h, w[8], d_SHA256_K56);
    roundSha256(h, a, b, c, d, e, f, g, w[9], d_SHA256_K57);
    roundSha256(g, h, a, b, c, d, e, f, w[10], d_SHA256_K58);
    roundSha256(f, g, h, a, b, c, d, e, w[11], d_SHA256_K59);
    roundSha256(e, f, g, h, a, b, c, d, w[12], d_SHA256_K60);
    roundSha256(d, e, f, g, h, a, b, c, w[13], d_SHA256_K61);
    roundSha256(c, d, e, f, g, h, a, b, w[14], d_SHA256_K62);
    roundSha256(b, c, d, e, f, g, h, a, w[15], d_SHA256_K63);

    digest[0] = a + d_IV0;
    digest[1] = b + d_IV1;
    digest[2] = c + d_IV2;
    digest[3] = d + d_IV3;
    digest[4] = e + d_IV4;
    digest[5] = f + d_IV5;
    digest[6] = g + d_IV6;
    digest[7] = h + d_IV7;
}

__device__ __forceinline__ void sha256PrivateKeyBase(const uint2& p, uint256_t& digest)
{
    uint32_t w[16]{};

    w[0] = p.x;
    w[1] = p.y;
    w[2] = 0x80000000; // Padding bit
    w[15] = sizeof(uint2) * 8; // Message length in bits

    uint32_t a{d_IV0};
    uint32_t b{d_IV1};
    uint32_t c{d_IV2};
    uint32_t d{d_IV3};
    uint32_t e{d_IV4};
    uint32_t f{d_IV5};
    uint32_t g{d_IV6};
    uint32_t h{d_IV7};

    roundSha256(a, b, c, d, e, f, g, h, w[0], d_SHA256_K0);
    roundSha256(h, a, b, c, d, e, f, g, w[1], d_SHA256_K1);
    roundSha256(g, h, a, b, c, d, e, f, w[2], d_SHA256_K2);
    roundSha256(f, g, h, a, b, c, d, e, w[3], d_SHA256_K3);
    roundSha256(e, f, g, h, a, b, c, d, w[4], d_SHA256_K4);
    roundSha256(d, e, f, g, h, a, b, c, w[5], d_SHA256_K5);
    roundSha256(c, d, e, f, g, h, a, b, w[6], d_SHA256_K6);
    roundSha256(b, c, d, e, f, g, h, a, w[7], d_SHA256_K7);
    roundSha256(a, b, c, d, e, f, g, h, w[8], d_SHA256_K8);
    roundSha256(h, a, b, c, d, e, f, g, 0, d_SHA256_K9);
    roundSha256(g, h, a, b, c, d, e, f, 0, d_SHA256_K10);
    roundSha256(f, g, h, a, b, c, d, e, 0, d_SHA256_K11);
    roundSha256(e, f, g, h, a, b, c, d, 0, d_SHA256_K12);
    roundSha256(d, e, f, g, h, a, b, c, 0, d_SHA256_K13);
    roundSha256(c, d, e, f, g, h, a, b, 0, d_SHA256_K14);
    roundSha256(b, c, d, e, f, g, h, a, w[15], d_SHA256_K15);

    w[0] = w[0] + s0(w[1]) + 0 + s1(0);
    w[1] = w[1] + s0(w[2]) + 0 + s1(w[15]);
    w[2] = w[2] + s0(w[3]) + 0 + s1(w[0]);
    w[3] = w[3] + s0(w[4]) + 0 + s1(w[1]);
    w[4] = w[4] + s0(w[5]) + 0 + s1(w[2]);
    w[5] = w[5] + s0(w[6]) + 0 + s1(w[3]);
    w[6] = w[6] + s0(w[7]) + w[15] + s1(w[4]);
    w[7] = w[7] + s0(w[8]) + w[0] + s1(w[5]);
    w[8] = w[8] + s0(0) + w[1] + s1(w[6]);
    w[9] = 0 + s0(0) + w[2] + s1(w[7]);
    w[10] = 0 + s0(0) + w[3] + s1(w[8]);
    w[11] = 0 + s0(0) + w[4] + s1(w[9]);
    w[12] = 0 + s0(0) + w[5] + s1(w[10]);
    w[13] = 0 + s0(0) + w[6] + s1(w[11]);
    w[14] = 0 + s0(w[15]) + w[7] + s1(w[12]);
    w[15] = w[15] + s0(w[0]) + w[8] + s1(w[13]);

    roundSha256(a, b, c, d, e, f, g, h, w[0], d_SHA256_K16);
    roundSha256(h, a, b, c, d, e, f, g, w[1], d_SHA256_K17);
    roundSha256(g, h, a, b, c, d, e, f, w[2], d_SHA256_K18);
    roundSha256(f, g, h, a, b, c, d, e, w[3], d_SHA256_K19);
    roundSha256(e, f, g, h, a, b, c, d, w[4], d_SHA256_K20);
    roundSha256(d, e, f, g, h, a, b, c, w[5], d_SHA256_K21);
    roundSha256(c, d, e, f, g, h, a, b, w[6], d_SHA256_K22);
    roundSha256(b, c, d, e, f, g, h, a, w[7], d_SHA256_K23);
    roundSha256(a, b, c, d, e, f, g, h, w[8], d_SHA256_K24);
    roundSha256(h, a, b, c, d, e, f, g, w[9], d_SHA256_K25);
    roundSha256(g, h, a, b, c, d, e, f, w[10], d_SHA256_K26);
    roundSha256(f, g, h, a, b, c, d, e, w[11], d_SHA256_K27);
    roundSha256(e, f, g, h, a, b, c, d, w[12], d_SHA256_K28);
    roundSha256(d, e, f, g, h, a, b, c, w[13], d_SHA256_K29);
    roundSha256(c, d, e, f, g, h, a, b, w[14], d_SHA256_K30);
    roundSha256(b, c, d, e, f, g, h, a, w[15], d_SHA256_K31);

    w[0] = w[0] + s0(w[1]) + w[9] + s1(w[14]);
    w[1] = w[1] + s0(w[2]) + w[10] + s1(w[15]);
    w[2] = w[2] + s0(w[3]) + w[11] + s1(w[0]);
    w[3] = w[3] + s0(w[4]) + w[12] + s1(w[1]);
    w[4] = w[4] + s0(w[5]) + w[13] + s1(w[2]);
    w[5] = w[5] + s0(w[6]) + w[14] + s1(w[3]);
    w[6] = w[6] + s0(w[7]) + w[15] + s1(w[4]);
    w[7] = w[7] + s0(w[8]) + w[0] + s1(w[5]);
    w[8] = w[8] + s0(w[9]) + w[1] + s1(w[6]);
    w[9] = w[9] + s0(w[10]) + w[2] + s1(w[7]);
    w[10] = w[10] + s0(w[11]) + w[3] + s1(w[8]);
    w[11] = w[11] + s0(w[12]) + w[4] + s1(w[9]);
    w[12] = w[12] + s0(w[13]) + w[5] + s1(w[10]);
    w[13] = w[13] + s0(w[14]) + w[6] + s1(w[11]);
    w[14] = w[14] + s0(w[15]) + w[7] + s1(w[12]);
    w[15] = w[15] + s0(w[0]) + w[8] + s1(w[13]);

    roundSha256(a, b, c, d, e, f, g, h, w[0], d_SHA256_K32);
    roundSha256(h, a, b, c, d, e, f, g, w[1], d_SHA256_K33);
    roundSha256(g, h, a, b, c, d, e, f, w[2], d_SHA256_K34);
    roundSha256(f, g, h, a, b, c, d, e, w[3], d_SHA256_K35);
    roundSha256(e, f, g, h, a, b, c, d, w[4], d_SHA256_K36);
    roundSha256(d, e, f, g, h, a, b, c, w[5], d_SHA256_K37);
    roundSha256(c, d, e, f, g, h, a, b, w[6], d_SHA256_K38);
    roundSha256(b, c, d, e, f, g, h, a, w[7], d_SHA256_K39);
    roundSha256(a, b, c, d, e, f, g, h, w[8], d_SHA256_K40);
    roundSha256(h, a, b, c, d, e, f, g, w[9], d_SHA256_K41);
    roundSha256(g, h, a, b, c, d, e, f, w[10], d_SHA256_K42);
    roundSha256(f, g, h, a, b, c, d, e, w[11], d_SHA256_K43);
    roundSha256(e, f, g, h, a, b, c, d, w[12], d_SHA256_K44);
    roundSha256(d, e, f, g, h, a, b, c, w[13], d_SHA256_K45);
    roundSha256(c, d, e, f, g, h, a, b, w[14], d_SHA256_K46);
    roundSha256(b, c, d, e, f, g, h, a, w[15], d_SHA256_K47);

    w[0] = w[0] + s0(w[1]) + w[9] + s1(w[14]);
    w[1] = w[1] + s0(w[2]) + w[10] + s1(w[15]);
    w[2] = w[2] + s0(w[3]) + w[11] + s1(w[0]);
    w[3] = w[3] + s0(w[4]) + w[12] + s1(w[1]);
    w[4] = w[4] + s0(w[5]) + w[13] + s1(w[2]);
    w[5] = w[5] + s0(w[6]) + w[14] + s1(w[3]);
    w[6] = w[6] + s0(w[7]) + w[15] + s1(w[4]);
    w[7] = w[7] + s0(w[8]) + w[0] + s1(w[5]);
    w[8] = w[8] + s0(w[9]) + w[1] + s1(w[6]);
    w[9] = w[9] + s0(w[10]) + w[2] + s1(w[7]);
    w[10] = w[10] + s0(w[11]) + w[3] + s1(w[8]);
    w[11] = w[11] + s0(w[12]) + w[4] + s1(w[9]);
    w[12] = w[12] + s0(w[13]) + w[5] + s1(w[10]);
    w[13] = w[13] + s0(w[14]) + w[6] + s1(w[11]);
    w[14] = w[14] + s0(w[15]) + w[7] + s1(w[12]);
    w[15] = w[15] + s0(w[0]) + w[8] + s1(w[13]);

    roundSha256(a, b, c, d, e, f, g, h, w[0], d_SHA256_K48);
    roundSha256(h, a, b, c, d, e, f, g, w[1], d_SHA256_K49);
    roundSha256(g, h, a, b, c, d, e, f, w[2], d_SHA256_K50);
    roundSha256(f, g, h, a, b, c, d, e, w[3], d_SHA256_K51);
    roundSha256(e, f, g, h, a, b, c, d, w[4], d_SHA256_K52);
    roundSha256(d, e, f, g, h, a, b, c, w[5], d_SHA256_K53);
    roundSha256(c, d, e, f, g, h, a, b, w[6], d_SHA256_K54);
    roundSha256(b, c, d, e, f, g, h, a, w[7], d_SHA256_K55);
    roundSha256(a, b, c, d, e, f, g, h, w[8], d_SHA256_K56);
    roundSha256(h, a, b, c, d, e, f, g, w[9], d_SHA256_K57);
    roundSha256(g, h, a, b, c, d, e, f, w[10], d_SHA256_K58);
    roundSha256(f, g, h, a, b, c, d, e, w[11], d_SHA256_K59);
    roundSha256(e, f, g, h, a, b, c, d, w[12], d_SHA256_K60);
    roundSha256(d, e, f, g, h, a, b, c, w[13], d_SHA256_K61);
    roundSha256(c, d, e, f, g, h, a, b, w[14], d_SHA256_K62);
    roundSha256(b, c, d, e, f, g, h, a, w[15], d_SHA256_K63);

    digest[0] = a + d_IV0;
    digest[1] = b + d_IV1;
    digest[2] = c + d_IV2;
    digest[3] = d + d_IV3;
    digest[4] = e + d_IV4;
    digest[5] = f + d_IV5;
    digest[6] = g + d_IV6;
    digest[7] = h + d_IV7;
}
