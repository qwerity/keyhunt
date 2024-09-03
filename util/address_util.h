#pragma once

#include "secp256k1.h"

namespace Address
{
    std::string fromPublicKey(const secp256k1::ecpoint &p, bool compressed = false);
    bool verifyAddress(const std::string &address);
};

namespace Base58
{
    std::string toBase58(const secp256k1::uint256 &x);
    secp256k1::uint256 toBigInt(const std::string &s);
    void getMinMaxFromPrefix(const std::string &prefix, secp256k1::uint256 &minValueOut, secp256k1::uint256 &maxValueOut);
    void toHash160(const std::string &s, uint32_t hash[5]);
    bool isBase58(std::string s);
};

namespace Hash
{
    void hashPublicKey(const secp256k1::ecpoint &p, uint32_t *digest);
    void hashPublicKeyCompressed(const secp256k1::ecpoint &p, uint32_t *digest);
    void hashPublicKey(const uint32_t *x, const uint32_t *y, uint32_t *digest);
    void hashPublicKeyCompressed(const uint32_t *x, const uint32_t *y, uint32_t *digest);
};
