#pragma once

#include "util/common_host.h"

#include <string>
#include <memory>
#include <vector>
#include <set>

// Wallet structure
// m / purpose' / coin_type' / account' / change / address_index
using bip32Path = std::vector<uint32_t>;
using bip32Paths = std::set<bip32Path>;

class HDWallet
{
public:
    HDWallet(const std::shared_ptr<GlobalContext>& context);
    ~HDWallet();

    HDWallet(const HDWallet&) = delete;
    HDWallet& operator=(const HDWallet&) = delete;

    HDWallet(HDWallet&& rhs) noexcept;
    HDWallet& operator=(HDWallet&& rhs) noexcept;

    static std::vector<uint8_t> generateEntropy(size_t bytes);
    static std::string generateMnemonic(const std::vector<uint8_t>& entropy);
    
private:
    struct Impl;
    std::unique_ptr<Impl> mImpl;
};