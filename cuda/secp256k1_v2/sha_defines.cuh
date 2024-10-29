#pragma once

/* Two of six logical functions used in SHA-1, SHA-256, SHA-384, and SHA-512: */
#define SHAF1(x, y, z)    (((x) & (y)) ^ ((~(x)) & (z)))
#define SHAF0(x, y, z)    (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
/* Shift-right (used in SHA-256, SHA-384, and SHA-512): */
#define SHR(b, x)        ((x) >> (b))
/* 32-bit Rotate-right (used in SHA-256): */
#define ROTR32(b, x)    (((x) >> (b)) | ((x) << (32 - (b))))
/* 64-bit Rotate-right (used in SHA-384 and SHA-512): */
#define ROTR64(b, x)    (((x) >> (b)) | ((x) << (64 - (b))))
/* Four of six logical functions used in SHA-384 and SHA-512: */
#define REVERSE32(w, x)    { \
    uint32_t tmp = (w); \
    tmp = (tmp >> 16) | (tmp << 16); \
    (x) = ((tmp & 0xff00ff00UL) >> 8) | ((tmp & 0x00ff00ffUL) << 8); \
}
#define REVERSE64(w, x)    { \
    uint64_t tmp = (w); \
    tmp = (tmp >> 32) | (tmp << 32); \
    tmp = ((tmp & 0xff00ff00ff00ff00UL) >> 8) | \
          ((tmp & 0x00ff00ff00ff00ffUL) << 8); \
    (x) = ((tmp & 0xffff0000ffff0000UL) >> 16) | \
          ((tmp & 0x0000ffff0000ffffUL) << 16); \
}
/* Four of six logical functions used in SHA-384 and SHA-512: */
#define SHA512_S0(x)    (ROTR64(28, (x)) ^ ROTR64(34, (x)) ^ ROTR64(39, (x)))
#define SHA512_S1(x)    (ROTR64(14, (x)) ^ ROTR64(18, (x)) ^ ROTR64(41, (x)))
#define little_s0(x)    (ROTR64( 1, (x)) ^ ROTR64( 8, (x)) ^ SHR( 7,   (x)))
#define little_s1(x)    (ROTR64(19, (x)) ^ ROTR64(61, (x)) ^ SHR( 6,   (x)))

#define mod(x, y) ((x)-((x)/(y)*(y)))
#define shr32(x, n) ((x) >> (n))
#define rotl32(n, d) (((n) << (d)) | ((n) >> (32 - (d))))
#define rotl64(n, d) (((n) << (d)) | ((n) >> (64 - (d))))
#define rotr64(n, d) (((n) >> (d)) | ((n) << (64 - (d))))
#define S0(x) (rotl32 ((x), 25u) ^ rotl32 ((x), 14u) ^ shr32 ((x),  3u))
#define S1(x) (rotl32 ((x), 15u) ^ rotl32 ((x), 13u) ^ shr32 ((x), 10u))
#define S2(x) (rotl32 ((x), 30u) ^ rotl32 ((x), 19u) ^ rotl32 ((x), 10u))
#define S3(x) (rotl32 ((x), 26u) ^ rotl32 ((x), 21u) ^ rotl32 ((x),  7u))

#define highBit(i) (0x0000000000000001ULL << (8*(i) + 7))
#define fBytes(i)  (0xFFFFFFFFFFFFFFFFULL >> (8 * (8-(i))))

#define SHA256_STEP(F0a, F1a, a, b, c, d, e, f, g, h, x, K) { h += K; h += x; h += S3 (e); h += F1a (e,f,g); d += h; h += S2 (a); h += F0a (a,b,c); }
#define SHA256_EXPAND(x, y, z, w) (S1 (x) + y + S0 (z) + w)

#define SHA512_STEP(a, b, c, d, e, f, g, h, x, K) { h += K + SHA512_S1(e) + SHAF1(e, f, g) + x; d += h; h += SHA512_S0(a) + SHAF0(a, b, c);}
#define ROUND_STEP_SHA512(i) { \
    SHA512_STEP(a, b, c, d, e, f, g, h, W[i + 0], k_sha512[i +  0]); \
    SHA512_STEP(h, a, b, c, d, e, f, g, W[i + 1], k_sha512[i +  1]); \
    SHA512_STEP(g, h, a, b, c, d, e, f, W[i + 2], k_sha512[i +  2]); \
    SHA512_STEP(f, g, h, a, b, c, d, e, W[i + 3], k_sha512[i +  3]); \
    SHA512_STEP(e, f, g, h, a, b, c, d, W[i + 4], k_sha512[i +  4]); \
    SHA512_STEP(d, e, f, g, h, a, b, c, W[i + 5], k_sha512[i +  5]); \
    SHA512_STEP(c, d, e, f, g, h, a, b, W[i + 6], k_sha512[i +  6]); \
    SHA512_STEP(b, c, d, e, f, g, h, a, W[i + 7], k_sha512[i +  7]); \
    SHA512_STEP(a, b, c, d, e, f, g, h, W[i + 8], k_sha512[i +  8]); \
    SHA512_STEP(h, a, b, c, d, e, f, g, W[i + 9], k_sha512[i +  9]); \
    SHA512_STEP(g, h, a, b, c, d, e, f, W[i + 10], k_sha512[i + 10]);\
    SHA512_STEP(f, g, h, a, b, c, d, e, W[i + 11], k_sha512[i + 11]);\
    SHA512_STEP(e, f, g, h, a, b, c, d, W[i + 12], k_sha512[i + 12]);\
    SHA512_STEP(d, e, f, g, h, a, b, c, W[i + 13], k_sha512[i + 13]);\
    SHA512_STEP(c, d, e, f, g, h, a, b, W[i + 14], k_sha512[i + 14]);\
    SHA512_STEP(b, c, d, e, f, g, h, a, W[i + 15], k_sha512[i + 15]);\
}
#define ROUND_STEP_SHA512_SHARED(i) { \
    SHA512_STEP(a, b, c, d, e, f, g, h, W_data[i + 0], k_sha512[i +  0]); \
    SHA512_STEP(h, a, b, c, d, e, f, g, W_data[i + 1], k_sha512[i +  1]); \
    SHA512_STEP(g, h, a, b, c, d, e, f, W_data[i + 2], k_sha512[i +  2]); \
    SHA512_STEP(f, g, h, a, b, c, d, e, W_data[i + 3], k_sha512[i +  3]); \
    SHA512_STEP(e, f, g, h, a, b, c, d, W_data[i + 4], k_sha512[i +  4]); \
    SHA512_STEP(d, e, f, g, h, a, b, c, W_data[i + 5], k_sha512[i +  5]); \
    SHA512_STEP(c, d, e, f, g, h, a, b, W_data[i + 6], k_sha512[i +  6]); \
    SHA512_STEP(b, c, d, e, f, g, h, a, W_data[i + 7], k_sha512[i +  7]); \
    SHA512_STEP(a, b, c, d, e, f, g, h, W_data[i + 8], k_sha512[i +  8]); \
    SHA512_STEP(h, a, b, c, d, e, f, g, W_data[i + 9], k_sha512[i +  9]); \
    SHA512_STEP(g, h, a, b, c, d, e, f, W_data[i + 10], k_sha512[i + 10]); \
    SHA512_STEP(f, g, h, a, b, c, d, e, W_data[i + 11], k_sha512[i + 11]); \
    SHA512_STEP(e, f, g, h, a, b, c, d, W_data[i + 12], k_sha512[i + 12]); \
    SHA512_STEP(d, e, f, g, h, a, b, c, W_data[i + 13], k_sha512[i + 13]); \
    SHA512_STEP(c, d, e, f, g, h, a, b, W_data[i + 14], k_sha512[i + 14]); \
    SHA512_STEP(b, c, d, e, f, g, h, a, W_data[i + 15], k_sha512[i + 15]); \
}

#define ROUND_EXPAND() { \
    w0_t = SHA256_EXPAND (we_t, w9_t, w1_t, w0_t); \
    w1_t = SHA256_EXPAND (wf_t, wa_t, w2_t, w1_t); \
    w2_t = SHA256_EXPAND (w0_t, wb_t, w3_t, w2_t); \
    w3_t = SHA256_EXPAND (w1_t, wc_t, w4_t, w3_t); \
    w4_t = SHA256_EXPAND (w2_t, wd_t, w5_t, w4_t); \
    w5_t = SHA256_EXPAND (w3_t, we_t, w6_t, w5_t); \
    w6_t = SHA256_EXPAND (w4_t, wf_t, w7_t, w6_t); \
    w7_t = SHA256_EXPAND (w5_t, w0_t, w8_t, w7_t); \
    w8_t = SHA256_EXPAND (w6_t, w1_t, w9_t, w8_t); \
    w9_t = SHA256_EXPAND (w7_t, w2_t, wa_t, w9_t); \
    wa_t = SHA256_EXPAND (w8_t, w3_t, wb_t, wa_t); \
    wb_t = SHA256_EXPAND (w9_t, w4_t, wc_t, wb_t); \
    wc_t = SHA256_EXPAND (wa_t, w5_t, wd_t, wc_t); \
    wd_t = SHA256_EXPAND (wb_t, w6_t, we_t, wd_t); \
    we_t = SHA256_EXPAND (wc_t, w7_t, wf_t, we_t); \
    wf_t = SHA256_EXPAND (wd_t, w8_t, w0_t, wf_t); \
}
#define ROUND_STEP(i) { \
    SHA256_STEP (SHAF0, SHAF1, a, b, c, d, e, f, g, h, w0_t, k_sha256[i +  0]); \
    SHA256_STEP (SHAF0, SHAF1, h, a, b, c, d, e, f, g, w1_t, k_sha256[i +  1]); \
    SHA256_STEP (SHAF0, SHAF1, g, h, a, b, c, d, e, f, w2_t, k_sha256[i +  2]); \
    SHA256_STEP (SHAF0, SHAF1, f, g, h, a, b, c, d, e, w3_t, k_sha256[i +  3]); \
    SHA256_STEP (SHAF0, SHAF1, e, f, g, h, a, b, c, d, w4_t, k_sha256[i +  4]); \
    SHA256_STEP (SHAF0, SHAF1, d, e, f, g, h, a, b, c, w5_t, k_sha256[i +  5]); \
    SHA256_STEP (SHAF0, SHAF1, c, d, e, f, g, h, a, b, w6_t, k_sha256[i +  6]); \
    SHA256_STEP (SHAF0, SHAF1, b, c, d, e, f, g, h, a, w7_t, k_sha256[i +  7]); \
    SHA256_STEP (SHAF0, SHAF1, a, b, c, d, e, f, g, h, w8_t, k_sha256[i +  8]); \
    SHA256_STEP (SHAF0, SHAF1, h, a, b, c, d, e, f, g, w9_t, k_sha256[i +  9]); \
    SHA256_STEP (SHAF0, SHAF1, g, h, a, b, c, d, e, f, wa_t, k_sha256[i + 10]); \
    SHA256_STEP (SHAF0, SHAF1, f, g, h, a, b, c, d, e, wb_t, k_sha256[i + 11]); \
    SHA256_STEP (SHAF0, SHAF1, e, f, g, h, a, b, c, d, wc_t, k_sha256[i + 12]); \
    SHA256_STEP (SHAF0, SHAF1, d, e, f, g, h, a, b, c, wd_t, k_sha256[i + 13]); \
    SHA256_STEP (SHAF0, SHAF1, c, d, e, f, g, h, a, b, we_t, k_sha256[i + 14]); \
    SHA256_STEP (SHAF0, SHAF1, b, c, d, e, f, g, h, a, wf_t, k_sha256[i + 15]); \
}
