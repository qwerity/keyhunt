#pragma once

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

namespace secp256k1
{
    // TODO(ksh): rename
    constexpr int uint256vSize{8};

    struct alignas(32) uint256
    {
        static constexpr int BigEndian = 1;
        static constexpr int LittleEndian = 2;

        uint32_t v[uint256vSize]{};

        ~uint256() = default;

        uint256() = default;

        uint256(const std::string &s)
        {
            std::string t = s;
            // 0x prefix
            if (t.length() >= 2 && ((t[0] == '0' && t[1] == 'x') || t[1] == 'X'))
            {
                t = t.substr(2);
            }
            // 'h' suffix
            if (!t.empty() && t[t.length() - 1] == 'h')
            {
                t = t.substr(0, t.length() - 1);
            }
            if (t.empty())
            {
                throw std::runtime_error("Incorrect hex formatting");
            }

            // Verify only valid hex characters
            for (const auto &tc : t)
            {
                if (!((tc >= 'a' && tc <= 'f') || (tc >= 'A' && tc <= 'F') || (tc >= '0' && tc <= '9')))
                {
                    throw std::runtime_error("Incorrect hex formatting");
                }
            }
            // Ensure the value is 64 hex digits. If it is longer, take the least-significant 64 hex digits.
            // If shorter, pad with 0's.
            if (t.length() > 64)
            {
                t = t.substr(t.length() - 64);
            }
            else if (t.length() < 64)
            {
                t = std::string(64 - t.length(), '0') + t;
            }

            const auto len = static_cast<int>(t.length());
            memset(v, 0, sizeof(uint32_t) * uint256vSize);
            int j = 0;
            for (int i = len - uint256vSize; i >= 0; i -= uint256vSize)
            {
                std::string sub = t.substr(i, uint256vSize);
                uint32_t val;
                if (sscanf(sub.c_str(), "%x", &val) != 1)
                {
                    throw std::runtime_error("Incorrect hex formatting");
                }
                v[j] = val;
                j++;
            }
        }

        explicit uint256(const uint32_t x)
        {
            memset(v, 0, sizeof(v));
            v[0] = x;
        }

        explicit uint256(const uint64_t x)
        {
            memset(v, 0, sizeof(v));
            v[0] = static_cast<uint32_t>(x);
            v[1] = static_cast<uint32_t>(x >> 32);
        }

        explicit uint256(const int x)
        {
            memset(v, 0, sizeof(v));
            v[0] = static_cast<uint32_t>(x);
        }

        uint256(const uint32_t x[uint256vSize], const int endian = LittleEndian)
        {
            if (endian == LittleEndian)
            {
                for (int i = 0; i < uint256vSize; i++)
                {
                    v[i] = x[i];
                }
            }
            else // BigEndian
            {
                for (int i = 0; i < uint256vSize; i++)
                {
                    v[i] = x[7 - i];
                }
            }
        }

        bool operator==(const uint256& other) const
        {
            return std::equal(std::begin(v), std::end(v), std::begin(other.v));
        }

        // Inequality operator
        bool operator!=(const uint256& other) const
        {
            return !(*this == other);
        }

        uint256& operator=(const uint256& other) = default;
        // {
        //     if (this != &other)
        //     {
        //         std::copy(std::begin(other.v), std::end(other.v), std::begin(v));
        //     }
        //     return *this;
        // }

        const uint32_t& operator[](const std::size_t index) const
        {
            return v[index];
        }

        uint32_t& operator[](const std::size_t index)
        {
            return v[index];
        }

        uint256 operator+(const uint256 &x) const
        {
            return add(x);
        }

        uint256 operator+(uint32_t x) const
        {
            return add(x);
        }

        uint256 operator*(uint32_t x) const
        {
            return mul(x);
        }

        uint256 operator*(const uint256 &x) const
        {
            return mul(x);
        }

        uint256 operator*(uint64_t x) const
        {
            return mul(x);
        }

        uint256 operator-(const uint256 &x) const
        {
            return sub(x);
        }

        void exportWords(uint32_t *buf, const int len, const int endian = LittleEndian) const
        {
            if (endian == LittleEndian)
            {
                for (int i = 0; i < len; i++)
                {
                    buf[i] = v[i];
                }
            }
            else
            {
                for (int i = 0; i < len; i++)
                {
                    buf[len - i - 1] = v[i];
                }
            }
        }

        [[nodiscard]] uint256 mul(const uint256 &val) const;
        [[nodiscard]] uint256 mul(uint32_t val) const;
        [[nodiscard]] uint256 mul(uint64_t val) const;
        [[nodiscard]] uint256 add(int val) const;
        [[nodiscard]] uint256 add(uint32_t val) const;
        [[nodiscard]] uint256 add(uint64_t val) const;
        [[nodiscard]] uint256 sub(int val) const;
        [[nodiscard]] uint256 sub(const uint256 &val) const;
        [[nodiscard]] uint256 add(const uint256 &val) const;
        [[nodiscard]] uint256 div(uint32_t val) const;
        [[nodiscard]] uint256 mod(uint32_t val) const;

        [[nodiscard]] uint32_t toInt32() const
        {
            return v[0];
        }

        [[nodiscard]] bool isZero() const
        {
            for (auto& i : v)
            {
                if (i != 0)
                {
                    return false;
                }
            }
            return true;
        }

        [[nodiscard]] int cmp(const uint256 &val) const
        {
            for (int i = 7; i >= 0; i--)
            {
                if (v[i] < val.v[i])
                {
                    // less than
                    return -1;
                }

                if (v[i] > val.v[i])
                {
                    // greater than
                    return 1;
                }
            }
            // equal
            return 0;
        }

        [[nodiscard]] int cmp(const uint32_t &val) const
        {
            // If any higher bits are set then it is greater
            for (int i = 7; i >= 1; i--)
            {
                if (v[i])
                {
                    return 1;
                }
            }

            if (v[0] > val)
            {
                return 1;
            }

            if (v[0] < val)
            {
                return -1;
            }

            return 0;
        }

        [[nodiscard]] uint256 pow(int n) const
        {
            uint256 product(1);
            uint256 square = *this;
            while (n)
            {
                if (n & 1)
                {
                    product = product.mul(square);
                }
                square = square.mul(square);
                n >>= 1;
            }
            return product;
        }

        [[nodiscard]] bool bit(int n) const
        {
            n = n % 256;
            return (v[n / 32] & (0x1 << (n % 32))) != 0;
        }

        [[nodiscard]] bool isEven() const
        {
            return (v[0] & 1) == 0;
        }

        [[nodiscard]] std::string toString(int base = 16) const;

        [[nodiscard]] uint64_t toUint64() const
        {
            return (static_cast<uint64_t>(v[1]) << 32) | v[0];
        }
    };

    constexpr uint32_t _POINT_AT_INFINITY_WORDS[uint256vSize] = {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF};
    constexpr uint32_t _P_WORDS[uint256vSize] = {0xFFFFFC2F, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF};
    constexpr uint32_t _N_WORDS[uint256vSize] = {0xD0364141, 0xBFD25E8C, 0xAF48A03B, 0xBAAEDCE6, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF};
    constexpr uint32_t _GX_WORDS[uint256vSize] = {0x16F81798, 0x59F2815B, 0x2DCE28D9, 0x029BFCDB, 0xCE870B07, 0x55A06295, 0xF9DCBBAC, 0x79BE667E};
    constexpr uint32_t _GY_WORDS[uint256vSize] = {0xFB10D4B8, 0x9C47D08F, 0xA6855419, 0xFD17B448, 0x0E1108A8, 0x5DA4FBFC, 0x26A3C465, 0x483ADA77};
    // TODO(ksh): not used
    // constexpr uint32_t _BETA_WORDS[uint256vSize] = {0x719501EE, 0xC1396C28, 0x12F58995, 0x9CF04975, 0xAC3434E9, 0x6E64479E, 0x657C0710, 0x7AE96A2B};
    // constexpr uint32_t _LAMBDA_WORDS[uint256vSize] = {0x1B23BD72, 0xDF02967C, 0x20816678, 0x122E22EA, 0x8812645A, 0xA5261C02, 0xC05C30E0, 0x5363AD4C};

    struct alignas(64) ecpoint
    {
        uint256 x{};
        uint256 y{};

        ~ecpoint() = default;

        ecpoint()
        {
            x = uint256(_POINT_AT_INFINITY_WORDS);
            y = uint256(_POINT_AT_INFINITY_WORDS);
        }

        ecpoint(const uint256 &x, const uint256 &y) : x(x), y(y) {}
        ecpoint(const ecpoint &p) = default;
        ecpoint& operator=(const ecpoint &p) = default;

        bool operator==(const ecpoint &p) const
        {
            return x == p.x && y == p.y;
        }

        bool operator!=(const ecpoint &p) const
        {
            return !(*this == p);
        }

        [[nodiscard]] std::string toString(bool compressed = false) const
        {
            if (!compressed)
            {
                return "04" + x.toString() + y.toString();
            }

            if (y.isEven())
            {
                return "02" + x.toString();
            }
            else
            {
                return "03" + x.toString();
            }
        }
    };

    const uint256 P(_P_WORDS);
    const uint256 N(_N_WORDS);

    // TODO(ksh): not used
    // const uint256 BETA(_BETA_WORDS);
    // const uint256 LAMBDA(_LAMBDA_WORDS);

    ecpoint pointAtInfinity();

    ecpoint G();

    uint256 negModP(const uint256 &x);
    uint256 negModN(const uint256 &x);
    uint256 addModP(const uint256 &a, const uint256 &b);
    uint256 subModP(const uint256 &a, const uint256 &b);
    uint256 multiplyModP(const uint256 &a, const uint256 &b);
    uint256 multiplyModN(const uint256 &a, const uint256 &b);
    ecpoint addPoints(const ecpoint &p, const ecpoint &q);
    ecpoint doublePoint(const ecpoint &p);
    uint256 invModP(const uint256 &x);
    bool isPointAtInfinity(const ecpoint &p);
    ecpoint multiplyPoint(const uint256 &k, const ecpoint &p);
    uint256 addModN(const uint256 &a, const uint256 &b);
    uint256 subModN(const uint256 &a, const uint256 &b);

    uint256 generatePrivateKey();

    bool pointExists(const ecpoint &p);

    void generateKeyPairsBulk(uint32_t count, const ecpoint &basePoint, std::vector<uint256> &privKeysOut, std::vector<ecpoint> &pubKeysOut);
    void generateKeyPairsBulk(const ecpoint &basePoint, std::vector<uint256> &privKeys, std::vector<ecpoint> &pubKeysOut);

    ecpoint parsePublicKey(const std::string &pubKeyString);
}
