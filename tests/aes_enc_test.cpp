#define CATCH_CONFIG_MAIN
#include <catch2/catch_all.hpp>

#include "util/crypto_util.h"
#include "util/utils.h"

#include <filesystem>
#include <iostream>
#include <cstdint>
#include <vector>

static const std::string key{"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"};
static const std::string iv{"cafebabefacedbaddecaf888"};

TEST_CASE("AES GCM enc/dec")
{
    const crypto::AES aesEnc(key, iv);

    const std::string plainText{"abcdefghijklmnopqurstqvwxyz"};

    std::vector<uint8_t> tag;
    std::vector<uint8_t> cipherText;
    REQUIRE(true == aesEnc.encrypt(plainText, tag, cipherText));

    std::string actualPlainText;
    REQUIRE(true == aesEnc.decrypt(cipherText, tag, actualPlainText));

    REQUIRE(plainText == actualPlainText);
}

TEST_CASE("AES GCM enc/dec file")
{
    std::error_code ec;
    const std::string resultsFile{"test_results.enc"};
    std::filesystem::remove_all(resultsFile, ec);

    const crypto::AES aesEnc(key, iv);

    const std::vector<std::string> plainTexts {
        {"abcdefghijklmnopqurstqvwxyz"},
        {"ksjfdgksjdf;kgjkjdfsj"},
        {"1"},
        {"0"},
    };

    for (const auto& plainText : plainTexts)
    {
        REQUIRE(true == utils::writeEncResultsToFile(aesEnc, resultsFile, plainText));
    }

    std::vector<std::string> results;
    REQUIRE(true == utils::readEncResults(aesEnc, resultsFile, results));
    REQUIRE(results.size() == plainTexts.size());
    for (uint32_t i = 0; i < results.size(); ++i)
    {
        REQUIRE(results[i] == plainTexts[i]);
    }

    std::filesystem::remove_all(resultsFile, ec);
}
