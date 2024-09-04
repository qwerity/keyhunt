#define CATCH_CONFIG_MAIN
#include <catch2/catch_all.hpp>

#include "secp256k1.h"
#include "address_util.h"

#include <iostream>
#include <cstdint>
#include <format>
#include <utility>
#include <vector>

#include "common.h"
#include "utils.h"

struct HashTest
{
    secp256k1::uint256 privateKey{};
    std::string hash160;                              // public key RIPEMD-160 hash
    std::string hash160Compressed;                    // compressed public key RIPEMD-160 hash
    std::string hash160WithoutFinalRound;             // public key RIPEMD-160 hash before converting to little endian
    std::string hash160WithoutFinalRoundCompressed;   // compressed public key RIPEMD-160 hash before converting to little endian

    HashTest(const std::string& key,
             std::string  hash160,
             std::string  hash160Compressed,
             std::string  hash160WithoutFinalRound,
             std::string  hash160WithoutFinalRoundCompressed)
        : privateKey(secp256k1::uint256(key)), // Assuming secp256k1::uint256 has a constructor that takes a string
          hash160(std::move(hash160)),
          hash160Compressed(std::move(hash160Compressed)),
          hash160WithoutFinalRound(std::move(hash160WithoutFinalRound)),
          hash160WithoutFinalRoundCompressed(std::move(hash160WithoutFinalRoundCompressed))
    {}
};

TEST_CASE("Test Ripemd-160 calculation from public key generated from private", "")
{
    std::vector<HashTest> hashTestVector {
        {"0100000000000000000000000000000000000000000000000000000000000000", "8e7682b1c4af85f1ecd61ab2288be0d54d0444df", "60afcdec519698a263417ddfe7cea936737a0ee7", "b182768ef185afc4b21ad6ecd5e08b28df44044d", "eccdaf60a2989651df7d416336a9cee7e70e7a73"},
        {"0100000000000000000000000000000000000000000000000000000000000200", "9f26a1af08f366906410ccdfca03d79f7e414eab", "0ea31dba6f1a8ae6499943d5581bf88e274881be", "afa1269f9066f308dfcc10649fd703caab4e417e", "ba1da30ee68a1a6fd54399498ef81b58be814827"},
        {"d7ae6ac85e67dfe75b3a42c6453abed4bb34a26d2988481fc134b2d845976a56", "6ca6bc1dd3b47a92302ea3ac743f191931be1bd4", "4b2c6447bac1b8da73aa010d1fa449472ba502c8", "1dbca66c927ab4d3aca32e3019193f74d41bbe31", "47642c4bdab8c1ba0d01aa734749a41fc802a52b"},
        {"f71485d0bff28cf3a9f1b6c2b65b03729f42f9818fb497c6fae7268bb124f263", "c1ae0d733b82a63799df6e5ce2b022134b521c59", "e92c5cb9dad37960a44f3d643ebc16da845f5d2a", "730daec137a6823b5c6edf991322b0e2591c524b", "b95c2ce96079d3da643d4fa4da16bc3e2a5d5f84"}
    };

    for (const auto&[privateKey, hash160, hash160Compressed, hash160WithoutFinalRound, hash160WithoutFinalRoundCompressed] : hashTestVector)
    {
        const auto p = secp256k1::multiplyPoint(privateKey, secp256k1::G());

        uint32_t xWords[8]{};
        uint32_t yWords[8]{};
        p.x.exportWords(xWords, 8, secp256k1::uint256::BigEndian);
        p.y.exportWords(yWords, 8, secp256k1::uint256::BigEndian);

        uint32_t digestWithoutFinalRound[5]{};
        uint32_t digestLE[5]{};
        Hash::hashPublicKey(xWords, yWords, digestWithoutFinalRound);
        std::ranges::transform(digestWithoutFinalRound, digestLE, utils::endian);

        uint32_t digestWithoutFinalRoundCompressed[5]{};
        uint32_t digestCompressedLE[5]{};
        Hash::hashPublicKeyCompressed(xWords, yWords, digestWithoutFinalRoundCompressed);
        std::ranges::transform(digestWithoutFinalRoundCompressed, digestCompressedLE, utils::endian);

        const auto actualHash160 = utils::convertToHexString(digestLE, 5);
        const auto actualHash160Compressed = utils::convertToHexString(digestCompressedLE, 5);
        const auto actualHash160WithoutFinalRound = utils::convertToHexString(digestWithoutFinalRound, 5);
        const auto actualHash160WithoutFinalRoundCompressed = utils::convertToHexString(digestWithoutFinalRoundCompressed, 5);

        REQUIRE(hash160 == actualHash160);
        REQUIRE(hash160Compressed == actualHash160Compressed);
        REQUIRE(hash160WithoutFinalRound == actualHash160WithoutFinalRound);
        REQUIRE(hash160WithoutFinalRoundCompressed == actualHash160WithoutFinalRoundCompressed);

        // std::cout << std::format("\"{}\", \"{}\", \"{}\", \"{}\"\n", actualHash160, actualHash160Compressed, actualHash160WithoutFinalRound, actualHash160WithoutFinalRoundCompressed);
    }
}
