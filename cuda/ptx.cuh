#pragma once

#include <cuda_runtime.h>
#include <cstdint>

#define madc_hi(dest, a, x, b) asm volatile("madc.hi.u32 %0, %1, %2, %3;\n\t" : "=r"(dest) : "r"(a), "r"(x), "r"(b))
#define madc_hi_cc(dest, a, x, b) asm volatile("madc.hi.cc.u32 %0, %1, %2, %3;\n\t" : "=r"(dest) : "r"(a), "r"(x), "r"(b))
#define mad_hi_cc(dest, a, x, b) asm volatile("mad.hi.cc.u32 %0, %1, %2, %3;\n\t" : "=r"(dest) : "r"(a), "r"(x), "r"(b))

#define mad_lo_cc(dest, a, x, b) asm volatile("mad.lo.cc.u32 %0, %1, %2, %3;\n\t" : "=r"(dest) : "r"(a), "r"(x), "r"(b))
#define madc_lo(dest, a, x, b) asm volatile("madc.lo.u32 %0, %1, %2, %3;\n\t" : "=r"(dest) : "r"(a), "r"(x), "r"(b))
#define madc_lo_cc(dest, a, x, b) asm volatile("madc.lo.cc.u32 %0, %1, %2, %3;\n\t" : "=r"(dest) : "r"(a), "r"(x),"r"(b))

#define addc(dest, a, b) asm volatile("addc.u32 %0, %1, %2;\n\t" : "=r"(dest) : "r"(a), "r"(b))
#define add_cc(dest, a, b) asm volatile("add.cc.u32 %0, %1, %2;\n\t" : "=r"(dest) : "r"(a), "r"(b))
#define addc_cc(dest, a, b) asm volatile("addc.cc.u32 %0, %1, %2;\n\t" : "=r"(dest) : "r"(a), "r"(b))

#define sub_cc(dest, a, b) asm volatile("sub.cc.u32 %0, %1, %2;\n\t" : "=r"(dest) : "r"(a), "r"(b))
#define subc_cc(dest, a, b) asm volatile("subc.cc.u32 %0, %1, %2;\n\t" : "=r"(dest) : "r"(a), "r"(b))
#define subc(dest, a, b) asm volatile("subc.u32 %0, %1, %2;\n\t" : "=r"(dest) : "r"(a), "r"(b))

#define set_eq(dest,a,b) asm volatile("set.eq.u32.u32 %0, %1, %2;\n\t" : "=r"(dest) : "r"(a), "r"(b))

#define lsbpos(x) (__ffs((x)))


__host__ __device__ __forceinline__ uint32_t SWAP32(uint32_t x)
{
    return (((x & 0x000000FF) << 24) |
            ((x & 0x0000FF00) << 8) |
            ((x & 0x00FF0000) >> 8) |
            ((x & 0xFF000000) >> 24));
}

__host__ __device__ __forceinline__ uint64_t SWAP64(uint64_t x)
{
    return ((((x & 0x00000000000000FFUL) << 56) |
             ((x & 0x000000000000FF00UL) << 40) |
             ((x & 0x0000000000FF0000UL) << 24) |
             ((x & 0x00000000FF000000UL) << 8)  |
             ((x & 0x000000FF00000000UL) >> 8)  |
             ((x & 0x0000FF0000000000UL) >> 24) |
             ((x & 0x00FF000000000000UL) >> 40) |
             ((x & 0xFF00000000000000UL) >> 56)));
}
