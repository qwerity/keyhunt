#include "bitcoin_utils.h"
#include "utils.h"
#include "wally_bip32.h"

#include "cuda/defines.h"

#include "bip/bip39_wordlist_english.h" // Add the BIP-39 wordlist as a header file.

#include <wally.hpp>

#include <boost/log/trivial.hpp>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

namespace
{
    std::vector<uint8_t> sha256(const std::vector<uint8_t> &data)
    {
        std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
        SHA256(data.data(), data.size(), hash.data());
        return hash;
    }
}

namespace bitcoin
{
    std::string keyToBase58(const ext_key& key, uint32_t serFlags)
    {
        unsigned char serialized_key[BIP32_SERIALIZED_LEN]{};

        // Serialize the BIP32 key
        int ret = bip32_key_serialize(&key, serFlags, serialized_key, BIP32_SERIALIZED_LEN);
        if (ret != WALLY_OK)
        {
            BOOST_LOG_TRIVIAL(error) << "Failed to serialize key: " << ret;
            return {};
        }

        // Convert serialized key to Base58Check
        char* base58_key = nullptr;
        utils::ScopeOutRunner outRunner([&base58_key](){ wally_free_string(base58_key); });

        ret = wally_base58_from_bytes(serialized_key, BIP32_SERIALIZED_LEN, BASE58_FLAG_CHECKSUM, &base58_key);
        if (ret != WALLY_OK)
        {
            BOOST_LOG_TRIVIAL(error) << "Failed to convert to Base58Check: " << ret;
            return {};
        }

        return {base58_key};
    }

    // BECH32: P2WPKH native SegWit address ("bc1...")
    std::string getP2WPKHAddress(const ext_key& key)
    {
        char *addressStr = nullptr;
        utils::ScopeOutRunner outRunner([&addressStr](){ wally_free_string(addressStr); });

        int ret = wally_bip32_key_to_addr_segwit(&key, "bc", 0, &addressStr);
        if (ret != WALLY_OK)
        {
            BOOST_LOG_TRIVIAL(error) << "Failed to generate address: " << ret;
            return {};
        }

        return addressStr;
    }

    // LEGACY: P2PKH address ("1...")
    std::string getP2PKHAddress(const ext_key& key)
    {
        char* address = nullptr;
        utils::ScopeOutRunner outRunner([&address](){ wally_free_string(address); });

        int ret = wally_bip32_key_to_address(&key, WALLY_ADDRESS_TYPE_P2PKH, WALLY_ADDRESS_VERSION_P2PKH_MAINNET, &address);
        if (ret != WALLY_OK)
        {
            BOOST_LOG_TRIVIAL(error) << "Failed to generate P2PKH address";
            return {};
        }

        return address;
    }

    // P2SH-P2WPKH wrapped SegWit address ("3...")
    std::string getP2SH_P2WPKHAddress(const ext_key& key)
    {
        char* address = nullptr;
        utils::ScopeOutRunner outRunner([&address](){ wally_free_string(address); });

        int ret = wally_bip32_key_to_address(&key, WALLY_ADDRESS_TYPE_P2SH_P2WPKH, WALLY_ADDRESS_VERSION_P2SH_MAINNET, &address);
        if (ret != WALLY_OK)
        {
            BOOST_LOG_TRIVIAL(error) << "Failed to generate P2SH P2WPKH address: " << ret;
            return {};
        }

        return address;
    }

    // Convert private key to WIF (Wallet Import Format)
    std::string privateKeyWIF(const ext_key& key)
    {
        // Convert to Base58Check (WIF format)
        char* wif = nullptr;
        utils::ScopeOutRunner outRunner([&wif](){ wally_free_string(wif); });

        int ret = wally_wif_from_bytes(key.priv_key + 1, EC_PRIVATE_KEY_LEN, WALLY_ADDRESS_VERSION_WIF_MAINNET, WALLY_WIF_FLAG_COMPRESSED, &wif);
        if (ret != WALLY_OK)
        {
            BOOST_LOG_TRIVIAL(error) << "Failed to convert to WIF: " << ret;
            return {};
        }

        return wif;
    }

    std::string generateMnemonic(const std::vector<uint8_t> &entropy)
    {
        // std::vector<uint8_t> entropy(ENTROPY_BITS / 8);
        std::vector<uint8_t> checksum(SHA256_DIGEST_LENGTH);
        SHA256(entropy.data(), entropy.size(), checksum.data());

        // Calculate the number of entropy bits dynamically
        const uint32_t entropyBits = entropy.size() * 8;

        // Checksum is 1 bit per 32 bits of entropy
        const uint32_t checksumBits = entropyBits / 32;

        // Total bits (entropy + checksum)
        const uint32_t totalBits = entropyBits + checksumBits;

        // Number of words in the mnemonic (each word represents 11 bits)
        uint32_t words = totalBits / 11;

        // Combine entropy and checksum
        std::vector<uint8_t> data(entropy);
        data.push_back(checksum[0]); // Append the first byte of the checksum
        // Convert to 11-bit indices
        uint16_t index = 0;
        uint32_t bitCount = 0;
        std::string mnemonic;
        for (size_t i = 0; i < totalBits; ++i)
        {
            index = (index << 1) | ((data[i / 8] >> (7 - (i % 8))) & 1);
            bitCount++;
            if (bitCount == 11)
            {
                if (!mnemonic.empty()) mnemonic += " ";
                mnemonic += BIP39_WORDLIST_ENGLISH[index];
                index = 0;
                bitCount = 0;
            }
        }
        return mnemonic;
    }

    std::vector<uint8_t> mnemonicToSeed(const std::string &mnemonic, const std::string &passphrase)
    {
        constexpr char SEED_KEY[] = "mnemonic";
        auto salt = std::vector<uint8_t>(SEED_KEY, SEED_KEY + sizeof(SEED_KEY) - 1);
        salt.insert(salt.end(), passphrase.begin(), passphrase.end());

        constexpr size_t SEED_BYTES = 64; // BIP-39 seed size in bytes (512 bits)
        std::vector<uint8_t> seed(SEED_BYTES);
        PKCS5_PBKDF2_HMAC(mnemonic.c_str(), mnemonic.size(), salt.data(), salt.size(), 2048, EVP_sha512(), seed.size(), seed.data());
        return seed;
    }

    HDExtendedPrivateKey mnemonicSeedToExMasterKey(const std::vector<uint8_t> &seed)
    {
        constexpr char DERIVATION_KEY[] = "Bitcoin seed";

        unsigned int len = 0;
        HDExtendedPrivateKey masterKey;
        HMAC(EVP_sha512(), DERIVATION_KEY, sizeof(DERIVATION_KEY) - 1, seed.data(), seed.size(), &masterKey.key[0], &len);
        return masterKey;
    }

    std::string exMasterKeyToXPRV(const HDExtendedPrivateKey& exMasterKey)
    {
        constexpr uint8_t VERSION_BYTES[4] = {0x04, 0x88, 0xAD, 0xE4}; // Mainnet xprv version

        std::vector<uint8_t> payload(78);
        std::copy_n(VERSION_BYTES, 4, payload.begin()); // Version

        payload[4] = 0x00; // Depth
        std::fill(payload.begin() + 5, payload.begin() + 13, 0x00); // Parent fingerprint and child number
        std::ranges::copy(exMasterKey.chainCode, payload.begin() + 13);
        payload[45] = 0x00; // Leading byte for private key
        std::ranges::copy(exMasterKey.key, payload.begin() + 46);

        // Double SHA-256 for checksum
        auto checksum = sha256(sha256(payload));

        payload.insert(payload.end(), checksum.begin(), checksum.begin() + 4);

        // Base58Check encode
        char* base58_key = nullptr;
        utils::ScopeOutRunner outRunner([&base58_key](){ wally_free_string(base58_key); });
        if (WALLY_OK != wally_base58_from_bytes(payload.data(), BIP32_SERIALIZED_LEN, BASE58_FLAG_CHECKSUM, &base58_key))
        {
            return {};
        }

        return {base58_key};
    }

    void generateMnemonicExMasterKey(const std::vector<uint8_t> &entropy, HDExtendedPrivateKey& masterKey)
    {
        const std::string mnemonic = generateMnemonic(entropy);
        const auto seed = mnemonicToSeed(mnemonic, "");
        masterKey = mnemonicSeedToExMasterKey(seed);
    }

    HDExtendedPrivateKey generateMnemonicExMasterKey(const std::vector<uint8_t> &entropy)
    {
        HDExtendedPrivateKey masterKey;
        generateMnemonicExMasterKey(entropy, masterKey);
        return std::move(masterKey);
    }

    HDExtendedPrivateKey generateRandomExMasterKey(const uint32_t entropyBits)
    {
        std::vector<uint8_t> entropy(entropyBits / 8);
        utils::generateEntropy(entropy);

        HDExtendedPrivateKey masterKey;
        generateMnemonicExMasterKey(entropy, masterKey);
        return std::move(masterKey);
    }
}
