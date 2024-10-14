#define CATCH_CONFIG_MAIN
#include <catch2/catch_all.hpp>

#include "util/crypto_util.h"

#include <iostream>
#include <cstdint>
#include <utility>
#include <vector>
#include <vector_types.h>


TEST_CASE("AES GCM enc/dec")
{
    std::string key{"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"};
    std::string iv{"cafebabefacedbaddecaf888"};

    crypto::AES aesEnc(key, iv);

    const std::string plainText{"abcdefghijklmnopqurstqvwxyz"};

    std::vector<unsigned char> tag;
    std::vector<unsigned char> cipherText;
    REQUIRE(true == aesEnc.encrypt(plainText, tag, cipherText));

    std::string actualPlainText;
    REQUIRE(true == aesEnc.decrypt(cipherText, tag, actualPlainText));

    REQUIRE(plainText == actualPlainText);
}
