#include "address_util.h"

#include <map>

static const std::string BASE58_STRING = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

struct Base58Map
{
    static std::map<char, int> createBase58Map()
    {
        std::map<char, int> m;
        for (int i = 0; i < 58; i++)
        {
            m[BASE58_STRING[i]] = i;
        }
        return m;
    }

    static std::map<char, int> myMap;
};

std::map<char, int> Base58Map::myMap = Base58Map::createBase58Map();


/**
 * Converts a base58 string to uint256
 */
secp256k1::uint256 Base58::toBigInt(const std::string &s)
{
    secp256k1::uint256 value;
    for (uint32_t i = 0; i < s.length(); i++)
    {
        value = value.mul(58u);
        int c = Base58Map::myMap[s[i]];
        value = value.add(c);
    }
    return value;
}

auto Base58::toHash160(const std::string &s, uint32_t hash[5]) -> void
{
    secp256k1::uint256 value = toBigInt(s);
    uint32_t words[6]{};
    value.exportWords(words, 6, secp256k1::uint256::BigEndian);
    // Extract words, ignore checksum
    for (int i = 0; i < 5; i++)
    {
        hash[i] = words[i];
    }
}

bool Base58::isBase58(std::string s)
{
    for (uint32_t i = 0; i < s.length(); i++)
    {
        if (BASE58_STRING.find(s[i]) == std::string::npos)
        {
            return false;
        }
    }
    return true;
}

std::string Base58::toBase58(const secp256k1::uint256 &x)
{
    std::string s;
    secp256k1::uint256 value = x;
    //while(!value.isZero()) {
    for (uint32_t i = 0; i <= 32; i++)
    {
        secp256k1::uint256 digit = value.mod(58);
        uint32_t digitInt = digit.toInt32();
        s = BASE58_STRING[digitInt] + s;
        value = value.div(58);
    }
    return s;
}

void Base58::getMinMaxFromPrefix(const std::string &prefix, secp256k1::uint256 &minValueOut, secp256k1::uint256 &maxValueOut)
{
    secp256k1::uint256 minValue = toBigInt(prefix);
    int exponent = 1;
    // 2^192
    uint32_t expWords[] = {0, 0, 0, 0, 0, 0, 1, 0};
    secp256k1::uint256 exp(expWords);
    // Find the smallest 192-bit number that starts with the prefix. That is, the prefix multiplied
    // by some power of 58
    secp256k1::uint256 nextValue = minValue.mul(58u);
    while (nextValue.cmp(exp) < 0)
    {
        exponent++;
        minValue = nextValue;
        nextValue = nextValue.mul(58u);
    }

    secp256k1::uint256 diff = secp256k1::uint256(58).pow(exponent - 1).sub(1);
    secp256k1::uint256 maxValue = minValue.add(diff);
    if (maxValue.cmp(exp) > 0)
    {
        maxValue = exp.sub(1);
    }
    minValueOut = minValue;
    maxValueOut = maxValue;
}
