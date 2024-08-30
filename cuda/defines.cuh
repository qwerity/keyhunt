#pragma once

#include <cuda_runtime.h>
#include <thrust/iterator/iterator_facade.h>

struct __builtin_align__(32) uint256_t
{
    uint32_t v[8];
};

struct __builtin_align__(64) ECPoint
{
    uint32_t x[8];
    uint32_t y[8];
};

class __builtin_align__(32) uint256_t_
{
public:
    uint32_t v[8]{};

    // Default constructor
    // Default constructor
    __host__ __device__
    uint256_t_() = default;

    __host__ __device__
    ~uint256_t_() = default; // Trivial destructor

    // Parameterized constructor for easy initialization
    __host__ __device__
    uint256_t_(const uint32_t a0, const uint32_t a1, const uint32_t a2, const uint32_t a3,
              const uint32_t a4, const uint32_t a5, const uint32_t a6, const uint32_t a7)
    {
        v[0] = a0; v[1] = a1; v[2] = a2; v[3] = a3;
        v[4] = a4; v[5] = a5; v[6] = a6; v[7] = a7;
    }

    // Parameterized constructor for easy initialization
    __host__ __device__
    uint256_t_(const std::initializer_list<uint32_t> init)
    {
        int i = 0;
        for (auto it = init.begin(); it != init.end() && i < 8; ++it, ++i)
        {
            v[i] = *it;
        }
    }

    // Copy constructor (if necessary)
    __host__ __device__ uint256_t_(const uint256_t_ &other)
    {
        for (int i = 0; i < 8; ++i)
        {
            v[i] = other.v[i];
        }
    }

    // Assignment operator (if necessary)
    __host__ __device__ uint256_t_ &operator=(const uint256_t_ &other)
    {
        if (this != &other)
        {
            for (int i = 0; i < 8; ++i)
            {
                v[i] = other.v[i];
            }
        }
        return *this;
    }

    // Iterator definition using Thrust's iterator facade for random access
    class Iterator : public thrust::iterator_facade<
            Iterator,
            uint256_t_,
            thrust::random_access_traversal_tag,
            uint256_t_&,
            std::ptrdiff_t
        >
    {
    public:
        explicit __host__ __device__
        Iterator(uint256_t_* ptr) : ptr(ptr) {}

        // Required iterator interface
        __host__ __device__
        void increment() { ++ptr; }

        __host__ __device__
        void decrement() { --ptr; }

        __host__ __device__
        void advance(const std::ptrdiff_t n) { ptr += n; }

        __host__ __device__
        uint256_t_& dereference() const { return *ptr; }

        __host__ __device__
        std::ptrdiff_t distance_to(const Iterator& other) const { return other.ptr - ptr; }

        __host__ __device__
        bool equal(const Iterator& other) const { return ptr == other.ptr; }

    private:
        uint256_t_* ptr{nullptr};
    };

    // Begin and end methods to get iterators
    __host__ __device__
    Iterator begin() { return Iterator(this); }

    __host__ __device__
    Iterator end() { return Iterator(this + 1); }
};
