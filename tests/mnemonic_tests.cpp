#include <catch2/catch_all.hpp>

#include <wally_bip39.h>
#include <wally_bip32.h>
#include <wally_crypto.h>
#include <iostream>
#include <cstring>

#include <util/utils.h>
#include <util/bitcoin_utils.h>

#include <openssl/hmac.h>

#include "test_data.h"

TEST_CASE("Test WallyCore lib: mnemonic -> hd keys generation", "")
{
    wally_init(1);
    utils::ScopeOutRunner outRunner([](){
        wally_cleanup(1);
    });

    const char* mnemonic = "tennis hero student waste adapt where fall call amused mandate hat panel";

    // BIP39 wordlist (English)
    words* wordlist = nullptr;
    REQUIRE(WALLY_OK == bip39_get_wordlist(nullptr, &wordlist));

    // Verify the mnemonic is valid
    REQUIRE(WALLY_OK == bip39_mnemonic_validate(wordlist, mnemonic));

    // Passphrase (optional, can be empty)
    const char* passphrase = "";

    // Buffer for the seed (512 bits = 64 bytes)
    unsigned char seed[BIP39_SEED_LEN_512];
    memset(seed, 0, BIP39_SEED_LEN_512);

    // Generate the seed from the mnemonic
    REQUIRE(WALLY_OK == bip39_mnemonic_to_seed(mnemonic, passphrase, seed, BIP39_SEED_LEN_512, nullptr));

    REQUIRE("48a9daa56a2ebd1bcf9d0524fb96ea49217ecbad1fd12a065ad1996b103965826e3f9617dade34c48b927be05e3f5fae8009ac3576bcb7510d4c198b523cc646" == utils::toHex(seed, BIP39_SEED_LEN_512));

    char* hexOutput = nullptr;
    REQUIRE(WALLY_OK == wally_hex_from_bytes(seed, BIP39_SEED_LEN_512, &hexOutput));
    REQUIRE("48a9daa56a2ebd1bcf9d0524fb96ea49217ecbad1fd12a065ad1996b103965826e3f9617dade34c48b927be05e3f5fae8009ac3576bcb7510d4c198b523cc646" == std::string(hexOutput));
    REQUIRE(WALLY_OK == wally_free_string(hexOutput));

    // BIP32: Derive the root key from the seed
    ext_key root_key{};
    REQUIRE(WALLY_OK == bip32_key_from_seed(seed, BIP39_SEED_LEN_512, BIP32_VER_MAIN_PRIVATE, 0, &root_key));

    // Serialize the root key and convert to Base58Check (xprv format)
    REQUIRE("xprv9s21ZrQH143K3NnNxz2WPZ3UTVw8kEZDSSvxdiubKHVWaBbk8K6Q3LAbhWCHyAEqoJUXMq2RGqaTJNW8kxNg8GRQ1bDotct4RejcpCTGaQ9" == bitcoin::keyToBase58(root_key, BIP32_FLAG_KEY_PRIVATE));

    const std::string m0 = "m/0";
    ext_key m0Key{};
    REQUIRE(WALLY_OK == bip32_key_from_parent_path_str(&root_key, m0.c_str(), 0, BIP32_FLAG_KEY_PRIVATE, &m0Key));
    REQUIRE("c25ec8d53730cf453fa516cfe9ee4995c39318e0595dbcb15e4d877bde1a8630" == utils::toHex(m0Key.priv_key + 1, EC_PRIVATE_KEY_LEN));
    REQUIRE("afa3778cd632b207d5e17ba7f6eb409f326d6fe5d82d7c727c9ae77a89aee1ac" == utils::toHex(m0Key.chain_code, EC_PRIVATE_KEY_LEN));
    REQUIRE("03250897e9364b8a41376ec13b2a38f2102e03616c725bdc9a5628b0bf00b0db99" == utils::toHex(m0Key.pub_key, EC_PUBLIC_KEY_LEN));
    REQUIRE("2487e5b2c039c635a819b05a01cdf3e92d266293" == utils::toHex(m0Key.hash160, HASH160_LEN));

    const std::string accountPath = "m/44'/0'/0'";
    ext_key account_key{};
    REQUIRE(WALLY_OK == bip32_key_from_parent_path_str(&root_key, accountPath.c_str(), 0, BIP32_FLAG_KEY_PRIVATE, &account_key));
    REQUIRE("xprv9zNoAaZF9FTkZ1gLBNo2HJ3bZ8ndYa1UYeorVSgDKs2XFxn9fnTkKA8LuV8LyJGo8oKyJPCVRXXr4MMZN4fD79boakPZeFj71oHT8TXqfsD" == bitcoin::keyToBase58(account_key, BIP32_FLAG_KEY_PRIVATE));
    REQUIRE("xpub6DN9a668yd23mVkoHQL2eRzL7Ad7x2jKusjTHq5ptCZW8m7JDKmzrxSpkkv1ZLUmtTB81W7P1UHzPZCKxEYe3PwDKrQhYHYDnUBsbkDA2UA" == bitcoin::keyToBase58(account_key, BIP32_FLAG_KEY_PUBLIC));

    const std::string derivedPath0 = "m/44'/0'/0'/0/0";
    ext_key derived_key_0{};
    REQUIRE(WALLY_OK == bip32_key_from_parent_path_str(&root_key, derivedPath0.c_str(), 0, BIP32_FLAG_KEY_PRIVATE, &derived_key_0));
    REQUIRE("cb86368cd231fade954005cea5e74d30984555f8e7b8c9d39fa4178ca20f14bb" == utils::toHex(derived_key_0.priv_key + 1, EC_PRIVATE_KEY_LEN));
    REQUIRE("02e99aa61f6a094d77b42c0b162200211c38c9574519450b8a2e9bb3989121d674" == utils::toHex(derived_key_0.pub_key, EC_PUBLIC_KEY_LEN));
    REQUIRE("bc1qa7z9t9nc7lh28a2qyeqq6s5a0dgsp0s0u20cwy" == bitcoin::getP2WPKHAddress(derived_key_0));
    REQUIRE("1NqT2bfkCvvZNx9CGgjQW23721ecvrSXsA" == bitcoin::getP2PKHAddress(derived_key_0));
    REQUIRE("38534pf6qS6jZzUczURNGii9GwCxrF4MMe" == bitcoin::getP2SH_P2WPKHAddress(derived_key_0));
    REQUIRE("L43LQmCS3RdEHYXg9dZ4JjesYrho47SgXm24vJ6ttsJNZj2wEzfs" == bitcoin::privateKeyWIF(derived_key_0));

    const std::string derivedPath1 = "m/44'/0'/0'/0/1";
    ext_key derived_key_1{};
    REQUIRE(WALLY_OK == bip32_key_from_parent_path_str(&root_key, derivedPath1.c_str(), 0, BIP32_FLAG_KEY_PRIVATE, &derived_key_1));
    REQUIRE("a39ee7c5b74e8d70134e391c0c9ce1e2d58d09a605dcf62b4f9ef497e98a2e67" == utils::toHex(derived_key_1.priv_key + 1, EC_PRIVATE_KEY_LEN));
    REQUIRE("021b64db0ef68d3670605e4a5c750adb323a5583e95f25d98faf2d71190419a769" == utils::toHex(derived_key_1.pub_key, EC_PUBLIC_KEY_LEN));
    REQUIRE("bc1qthc5spu4p6u7yermq3mzt6q2yjhyvwc65ufsmh" == bitcoin::getP2WPKHAddress(derived_key_1));
    REQUIRE("19ZitN5YVRodncNEfmojHgS2P7rMzYRUSY" == bitcoin::getP2PKHAddress(derived_key_1));
    REQUIRE("3H7VFfCDUwEUnNQ6VnnKQ49jo8yofVsabe" == bitcoin::getP2SH_P2WPKHAddress(derived_key_1));
    REQUIRE("L2hmWSKbPPntRNCGsje7zH5VztP5ryJ9F62paj8Z8gUwtSMchuzL" == bitcoin::privateKeyWIF(derived_key_1));

    const std::string derivedPath3 = "m/84'/0'/0'/0/1";
    ext_key derived_key_3{};
    REQUIRE(WALLY_OK == bip32_key_from_parent_path_str(&root_key, derivedPath3.c_str(), 0, BIP32_FLAG_KEY_PRIVATE, &derived_key_3));
    REQUIRE("436e10d5bda9c8cc10756ad5689d55f72548037efe4a0f00a8ef80077f770eca" == utils::toHex(derived_key_3.priv_key + 1, EC_PRIVATE_KEY_LEN));
    REQUIRE("0390526498413c42a96328726bbc45e1d9011b73f814e3c10a0a8bb3d2b33d3dc4" == utils::toHex(derived_key_3.pub_key, EC_PUBLIC_KEY_LEN));
    REQUIRE("bc1q6vg78x8py29g5zl0ppljeu3e4n9u5w93ctk9s4" == bitcoin::getP2WPKHAddress(derived_key_3));
    REQUIRE("1LF31RuC46qMeReKDLT3Q9sVKmaNCQBj2N" == bitcoin::getP2PKHAddress(derived_key_3));
    REQUIRE("3ByX8NZaUbpocBnNUNVakgahNSTTtYCW2c" == bitcoin::getP2SH_P2WPKHAddress(derived_key_3));
    REQUIRE("KyUnXxdB9PmwCqvfGJiFCgXU1qEPNnzvZ9VETMwbpzNvQdm14PnY" == bitcoin::privateKeyWIF(derived_key_3));

    const std::string derivedPath4 = "m/49'/0'/0'/0/2";
    ext_key derived_key_4{};
    REQUIRE(WALLY_OK == bip32_key_from_parent_path_str(&root_key, derivedPath4.c_str(), 0, BIP32_FLAG_KEY_PRIVATE, &derived_key_4));
    REQUIRE("b54197c9eee699f9805d729d4a63df9cc468e4197b949617b16565d96ec1a092" == utils::toHex(derived_key_4.priv_key + 1, EC_PRIVATE_KEY_LEN));
    REQUIRE("0280576e2792d9bc82e701d4b458b76a8af0c702b1f68416697f3bd9622fc5a3af" == utils::toHex(derived_key_4.pub_key, EC_PUBLIC_KEY_LEN));
    REQUIRE("bc1q2chxxxshljwlka87j9lwlhzvccjswdfc0kkcl6" == bitcoin::getP2WPKHAddress(derived_key_4));
    REQUIRE("18rggXncvjaGvwX4FbSTqFKZfg7iJKdxPT" == bitcoin::getP2PKHAddress(derived_key_4));
    REQUIRE("38fR6RcPqsWr7hpeusMde1XacC2fyjVRNR" == bitcoin::getP2SH_P2WPKHAddress(derived_key_4));
    REQUIRE("L3J3p57yzZxucz5Q3Rns92Vdo2jrWT9ToJRpKX3LiszV6poHgUak" == bitcoin::privateKeyWIF(derived_key_4));
}

TEST_CASE("Test WallyCore lib: mnemonic -> list", "")
{
    wally_init(1);
    utils::ScopeOutRunner outRunner([](){
        wally_cleanup(1);
    });

    const char* mnemonic = mnemonicTestData.mnemonic.c_str();

    // BIP39 wordlist (English)
    words* wordlist = nullptr;
    REQUIRE(WALLY_OK == bip39_get_wordlist(nullptr, &wordlist));

    // Verify the mnemonic is valid
    REQUIRE(WALLY_OK == bip39_mnemonic_validate(wordlist, mnemonic));

    // Passphrase (optional, can be empty)
    const char* passphrase = "";

    // Buffer for the seed (512 bits = 64 bytes)
    unsigned char seed[BIP39_SEED_LEN_512];
    memset(seed, 0, BIP39_SEED_LEN_512);

    // Generate the seed from the mnemonic
    REQUIRE(WALLY_OK == bip39_mnemonic_to_seed(mnemonic, passphrase, seed, BIP39_SEED_LEN_512, nullptr));
    REQUIRE(mnemonicTestData.seed == utils::toHex(seed, BIP39_SEED_LEN_512));

    ext_key root_key{};
    REQUIRE(WALLY_OK == bip32_key_from_seed(seed, BIP39_SEED_LEN_512, BIP32_VER_MAIN_PRIVATE, 0, &root_key));

    for (const auto& data : mnemonicTestData.keysTestData)
    {
        ext_key derived_key{};
        REQUIRE(WALLY_OK == bip32_key_from_parent_path_str(&root_key, data.path.c_str(), 0, BIP32_FLAG_KEY_PRIVATE, &derived_key));
        REQUIRE(data.privateKey == utils::toHex(derived_key.priv_key + 1, EC_PRIVATE_KEY_LEN));
        REQUIRE(data.hash160 == utils::toHex(derived_key.hash160, HASH160_LEN));
        if (data.path.find("49") != std::string::npos)
        {
            REQUIRE(data.btcAddress == bitcoin::getP2SH_P2WPKHAddress(derived_key));
        }
        else
        {
            REQUIRE(data.btcAddress == bitcoin::getP2PKHAddress(derived_key));
        }
    }
}

struct ext_key derive_key_from_parent(const ext_key& parent_key, uint32_t addr_index)
{
    ext_key child_key{};

    // Derive the child key from the parent using the addr index
    int ret = bip32_key_from_parent(&parent_key, addr_index, BIP32_FLAG_KEY_PRIVATE, &child_key);
    if (ret != WALLY_OK)
    {
        std::cerr << "Error deriving child key for address index: " << addr_index << std::endl;
        return {};
    }

    // Print the derived private key
    std::cout << "Private Key (m/" << addr_index << "): " << bitcoin::privateKeyWIF(child_key) << std::endl;  // Skip the first byte (0x00)

    return child_key;
}

TEST_CASE("Check root key generation with OpenSSL")
{
    wally_init(1);
    utils::ScopeOutRunner outRunner([](){
        wally_cleanup(1);
    });

    const char* mnemonic = "tennis hero student waste adapt where fall call amused mandate hat panel";

    // BIP39 wordlist (English)
    words* wordlist = nullptr;
    REQUIRE(WALLY_OK == bip39_get_wordlist(nullptr, &wordlist));

    // Verify the mnemonic is valid
    REQUIRE(WALLY_OK == bip39_mnemonic_validate(wordlist, mnemonic));

    // Passphrase (optional, can be empty)
    const char* passphrase = "";

    // Buffer for the seed (512 bits = 64 bytes)
    unsigned char seed[BIP39_SEED_LEN_512]{0};

    // Generate the seed from the mnemonic
    REQUIRE(WALLY_OK == bip39_mnemonic_to_seed(mnemonic, passphrase, seed, BIP39_SEED_LEN_512, nullptr));

    unsigned char I[64]{0};  // Output from HMAC-SHA512
    unsigned int len{0};
    const unsigned char BITCOIN_SEED[] = "Bitcoin seed";
    HMAC(EVP_sha512(), BITCOIN_SEED, sizeof(BITCOIN_SEED) - 1, seed, BIP39_SEED_LEN_512, I, &len);

    std::vector<unsigned char> root_private_key(I, I + 32); // Root private key (first 32 bytes of I)
    std::vector<unsigned char> chain_code(I + 32, I + 64); // Chain code (last 32 bytes of I)

    // BIP32: Derive the root key from the seed
    ext_key root_key{};
    REQUIRE(WALLY_OK == bip32_key_from_seed(seed, BIP39_SEED_LEN_512, BIP32_VER_MAIN_PRIVATE, 0, &root_key));
    REQUIRE("98ca9c9345c45dbb69adaea3d52f1eedeb7b82ec6dc6ec178ece47d15f737c3a" == utils::toHex(root_key.priv_key + 1, EC_PRIVATE_KEY_LEN));
    REQUIRE("8459d6d7804b3afacec9929c35b1328f3ee0e7acfce0f7d268f03737480cbb96" == utils::toHex(root_key.chain_code, EC_PRIVATE_KEY_LEN));

    REQUIRE(0 == memcmp(root_private_key.data(), root_key.priv_key + 1, EC_PRIVATE_KEY_LEN));
    REQUIRE(0 == memcmp(chain_code.data(), root_key.chain_code, EC_PRIVATE_KEY_LEN));
}
