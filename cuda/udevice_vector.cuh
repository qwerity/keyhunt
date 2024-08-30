#pragma once

// #pragma hd_warning_disable

#include <thrust/device_vector.h>

#include <cassert>
#include <cuda_runtime_api.h>
#include <thrust/device_allocator.h>
#include <thrust/functional.h>
#include <thrust/host_vector.h>

namespace thrust
{
    // Occasionally, it is advantageous to avoid initializing the individual
    // elements of a device_vector. For example, the default behavior of
    // zero-initializing numeric data may introduce undesirable overhead.
    // This example demonstrates how to avoid default construction of a
    // device_vector's data by using a custom allocator.

    // uninitialized_allocator is an allocator which
    // derives from device_allocator and which has a
    // no-op construct member function
    template<typename T>
    struct uninitialized_allocator : thrust::device_allocator<T>
    {
        // the default generated constructors and destructors are implicitly
        // marked __host__ __device__, but the current Thrust device_allocator
        // can only be constructed and destroyed on the host; therefore, we
        // define these as host only
        __host__ uninitialized_allocator() = default;

        __host__ uninitialized_allocator(const uninitialized_allocator &other)
            : thrust::device_allocator<T>(other)
        {
        }

        __host__ ~uninitialized_allocator() = default;

        // for correctness, you should also redefine rebind when you inherit
        // from an allocator type; this way, if the allocator is rebound somewhere,
        // it's going to be rebound to the correct type - and not to its base
        // type for U
        template<typename U>
        struct rebind
        {
            typedef uninitialized_allocator<U> other;
        };

        // note that construct is annotated as
        // a __host__ __device__ function
        __host__ __device__ inline void construct(T *)
        {
            // no-op
        }
    };

    template<typename T>
    struct udevice_vector : public thrust::device_vector<T, uninitialized_allocator<T>>
    {
    private:
        using Parent = thrust::device_vector<T, uninitialized_allocator<T>>;

    public:
        /*! \cond
         */
        typedef typename Parent::size_type size_type;
        typedef typename Parent::value_type value_type;
        __host__ udevice_vector() : Parent()
        {
        }

        /*! The destructor erases the elements.
         */
        //  Define an empty destructor to explicitly specify
        //  its execution space qualifier, as a workaround for nvcc warning
        // __host__
        // ~udevice_vector() = default;

        /*! This constructor creates a \p device_vector with the given
         *  size.
         *  \param n The number of elements to initially create.
         */
        __host__ explicit udevice_vector(size_type n)
            : Parent(n)
        {
        }

        /*! This constructor creates a \p device_vector with copies
         *  of an exemplar element.
         *  \param n The number of elements to initially create.
         *  \param value An element to copy.
         */
        __host__ explicit udevice_vector(size_type n, const value_type &value)
            : Parent(n, value)
        {
        }

        /*! Copy constructor copies from an exemplar \p device_vector.
         *  \param v The \p device_vector to copy.
         */
        __host__ udevice_vector(const udevice_vector &v)
            : Parent(v)
        {
        }

        /*! Move constructor moves from another \p device_vector.
         *  \param v The device_vector to move.
         */
        __host__ udevice_vector(udevice_vector &&v) noexcept
            : Parent(std::move(v))
        {
        }

        template<typename InputIterator>
        __host__ udevice_vector(InputIterator first, InputIterator last)
            : Parent(first, last)
        {
        }

        /*! Copy constructor copies from an exemplar \p host_vector with possibly different type.
         *  \param v The \p host_vector to copy.
         */
        template<typename OtherT, typename OtherAlloc>
        __host__ explicit udevice_vector(const thrust::host_vector<OtherT, OtherAlloc> &v)
            : Parent(v)
        {
        }

        template<typename OtherT, typename OtherAlloc>
        __host__ udevice_vector<T>& operator=(const thrust::host_vector<OtherT, OtherAlloc>& v)
        {
            Parent::operator=(v);
            return *this;
        }

        __host__ udevice_vector<T>& operator=(udevice_vector<T>&& other) noexcept
        {
            Parent::operator=(std::move(other));
            return *this;
        }
    };

    template<class T>
    void release(thrust::udevice_vector<T> &d_vec)
    {
        thrust::udevice_vector<T> d_tmp;
        d_vec.swap(d_tmp);
    }
} // namespace thrust
