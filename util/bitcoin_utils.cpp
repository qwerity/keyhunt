#include "bitcoin_utils.h"
#include "utils.h"
#include "wally_bip32.h"

#include <wally.hpp>

#include <boost/log/trivial.hpp>

namespace bitcoin
{
    #define BIP32_KEY_LEN 33

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

        return base58_key;
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
}