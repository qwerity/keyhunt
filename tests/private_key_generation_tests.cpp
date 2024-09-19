#define CATCH_CONFIG_MAIN
#include <catch2/catch_all.hpp>

#include "util/common.h"
#include "util/crypto_util.h"
#include "util/utils.h"

#include "cuda/ecc.cuh"

TEST_CASE("check private key generation", "")
{
    std::unique_ptr mCuECC(std::make_unique<ECC>());
    mCuECC->initWithPrivateDefinedXRandomY(32, PointCompressionType::COMPRESSED, 2);

    const uint32_t keysNumberPerIteration = mCuECC->getKeysNumberPerIteration();
    const uint32_t privateXPart{1};
    const uint32_t iterationsNumber{2};

    for (uint32_t iteration = 0; iteration < iterationsNumber; ++iteration)
    {
        mCuECC->generatePrivateKeysForXPerIteration(privateXPart, iteration);

        thrust::host_vector<uint256_t> h_privateKeys;
        mCuECC->getPrivateKeys(h_privateKeys);
        for (uint32_t i = 0; i < h_privateKeys.size(); ++i)
        {
            uint32_t msg[16]{};
            uint32_t digest[8]{};

            msg[0] = utils::endian(privateXPart);
            msg[1] = utils::endian(i + (iteration * keysNumberPerIteration));
            msg[2] = 0x80000000;
            msg[15] = 8 * sizeof(uint2);

            crypto::sha256Init(digest);
            crypto::sha256(msg, digest);

            std::array<uint32_t, 8> actualSha256{};
            std::ranges::transform(digest, actualSha256.data(), utils::endian);

            const auto p = h_privateKeys[i];
            for (uint32_t k = 0; k < 8; ++k)
            {
                REQUIRE(actualSha256[k] == utils::endian(p.v[k]));
            }
        }
    }
}