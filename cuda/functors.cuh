#pragma once

#include <cstdint>
#include "defines.cuh"
#include "secp256k1.cuh"

struct InitializeECPoint
{
    __host__ __device__ ECPoint operator()(const uint32_t) const
    {
        ECPoint point;
        for (int i = 0; i < 8; ++i)
        {
            point.x[i] = 0xFFFFFFFF;
            point.y[i] = 0xFFFFFFFF;
        }
        return point;
    }
};


struct TransformGPoints
{
    const uint32_t *d_gPoints{nullptr};

    const uint32_t m_dataChunkSize{8 * sizeof(uint32_t)};
    const uint32_t m_depth{1};

    explicit TransformGPoints(const uint32_t *data) : d_gPoints(data)
    {}

    __device__ inline size_t operator()(size_t idx) const
    {
        // auto w = m_dataChunkSize;
        // auto row = idx / w;
        // auto col = (idx - row * w) / m_depth;
        //
        // auto start_address = (row * w) + col * m_depth;
        //
        // auto j = 0u;
        // auto pos = j + start_address;
        // auto val = d_gPoints[pos];
        // auto mid = pos;
        // for (auto _j = 1U; _j < m_depth; ++_j) {
        //     auto _pos = _j + start_address;
        //     auto tmp = d_data[_pos];
        //     if (tmp > val) {
        //         val = tmp;
        //         mid = _pos;
        //     }
        // }
        // return mid;

        return 0;
    }
};

struct splatBigIntFunctor
{
    uint32_t _gridSize{};
    uint32_t _blockSize{};

    splatBigIntFunctor()
    {

    }
    __device__
    secp256k1::uint256 operator()()
    {
        // uint32_t value[8]{};
        // i.exportWords(value, 8, secp256k1::uint256::BigEndian);
        // const uint32_t totalThreads = _gridSize * _blockSize;
        // const uint32_t threadId = block * _blockSize * 4 + thread * 4;
        // uint32_t index = threadId;
        // for (uint32_t k = 0; k < 4; k++)
        // {
        //     dest[index] = value[k];
        //     index++;
        // }
        //
        // index = base + totalThreads * 4 + threadId;
        // for (uint32_t k = 4; k < 8; k++)
        // {
        //     dest[index] = value[k];
        //     index++;
        // }
    }
};