#pragma once

#include <string>
#include <vector>
#include <cstdint>

struct ext_key;

namespace bitcoin
{
    std::string keyToBase58(const ext_key& key, uint32_t serFlags);

    // BECH32: P2WPKH native SegWit address ("bc1...")
    std::string getP2WPKHAddress(const ext_key& key);

    // LEGACY: P2PKH address ("1...")
    std::string getP2PKHAddress(const ext_key& key);

    // P2SH-P2WPKH wrapped SegWit address ("3...")
    std::string getP2SH_P2WPKHAddress(const ext_key& key);

    // Convert private key to WIF (Wallet Import Format)
    std::string privateKeyWIF(const ext_key& key);
}