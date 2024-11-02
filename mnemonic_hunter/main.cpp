#include "hd_wallet.h"

#include "util/utils.h"
#include "cuda/secp256k1_v2/bip32.cuh"

#include <wally_bip32.h>
#include <wally_bip39.h>

#include <iostream>
#include <vector>
#include <set>

using namespace std;

struct PathCompare
{
    bool operator()(const std::vector<uint32_t>& a, const std::vector<uint32_t>& b) const
    {
        if (a.size() != b.size())
        {
            return a.size() < b.size();
        }
        return a < b;
    }
};

// Helper function to expand a single pattern into all its combinations
std::vector<std::string> expand_pattern(const std::string& pattern, uint32_t accN, uint32_t addrN)
{
    std::vector<std::string> expanded;

    const string accountPlaceholder{"acc"};
    const uint32_t acc_placeholder_length = accountPlaceholder.size();
    const uint32_t acc_hardened_placeholder_length = acc_placeholder_length + 1;
    const string addressPlaceholder{"addr"};

    size_t acc_pos = pattern.find(accountPlaceholder);
    size_t addr_pos = pattern.find(addressPlaceholder);

    if (acc_pos == std::string::npos && addr_pos == std::string::npos)
    {
        expanded.push_back(pattern);
        return expanded;
    }

    // Handle account expansion
    std::vector<std::string> acc_expanded;
    if (acc_pos != std::string::npos)
    {
        bool is_hardened = (pattern[acc_pos + acc_placeholder_length] == '\'');
        const std::string& acc_pattern = pattern;
        for (uint32_t i = 0; i < accN; ++i)
        {
            std::string replacement = std::to_string(i) + (is_hardened ? "'" : "");
            std::string new_pattern = acc_pattern;
            new_pattern.replace(acc_pos, is_hardened ? acc_hardened_placeholder_length : acc_placeholder_length, replacement);
            acc_expanded.push_back(new_pattern);
        }
    }
    else
    {
        acc_expanded.push_back(pattern);
    }

    // Handle address expansion
    for (const auto& acc_pattern: acc_expanded)
    {
        addr_pos = acc_pattern.find(addressPlaceholder);
        if (addr_pos != std::string::npos)
        {
            for (uint32_t i = 0; i < addrN; ++i)
            {
                std::string new_pattern = acc_pattern;
                new_pattern.replace(addr_pos, addressPlaceholder.size(), std::to_string(i));
                expanded.push_back(new_pattern);
            }
        }
        else
        {
            expanded.push_back(acc_pattern);
        }
    }

    return expanded;
}

std::vector<uint32_t> get_derivation_vector(const std::string& pattern)
{
    std::vector<uint32_t> path(BIP32_PATH_MAX_LEN);
    size_t written;

    int result = bip32_path_from_str(pattern.c_str(), 0, 0, 0, path.data(), path.size(), &written);

    if (result != WALLY_OK)
    {
        throw std::runtime_error("Failed to parse BIP32 path: " + pattern);
    }

    path.resize(written);
    return path;
}

std::vector<std::vector<uint32_t>> get_all_derivation_paths(const std::vector<string>& expanded_patterns, uint32_t accN, uint32_t addrN)
{
    std::vector<std::vector<uint32_t>> all_paths;

    for (const auto& expanded: expanded_patterns)
    {
        all_paths.push_back(get_derivation_vector(expanded));
    }

    return all_paths;
}

// Utility function to print paths for verification
template <typename T>
void print_paths(const T& paths)
{
    for (const auto& path: paths)
    {
        if (!path.empty())
        {
            printf("m/");
        }
        for (size_t i = 0; i < path.size(); ++i)
        {
            printf("%u%s", path[i] & ~BIP32_INITIAL_HARDENED_CHILD, (path[i] & BIP32_INITIAL_HARDENED_CHILD) ? "'" : "");
            if (i < path.size() - 1)
            {
                printf("/");
            }
        }
        printf("\n");
    }
}

int main()
{
    utils::initOpenssl();

    constexpr int wallyInitFlags{0};

    // Initialize the Wally core library
    if (wally_init(wallyInitFlags) != WALLY_OK)
    {
        std::cerr << "Failed to initialize Wally\n";
        return 1;
    }
    utils::ScopeOutRunner outRunner([]() {
        wally_cleanup(wallyInitFlags);
        utils::releaseOpenssl();
    });

    // Config will initialize here
    auto context = std::make_shared<GlobalContext>();
    if (!context->config.isLoaded())
    {
        return 1;
    }

    HDWallet hdWallet(context);
    {
        HDWalletConfig& hdWalletConfig = context->config.hdWallet();

        std::vector<std::string> expanded_patterns;
        for (const auto& pattern: hdWalletConfig.derivationPathsPatters)
        {
            auto exp = expand_pattern(pattern, hdWalletConfig.accountsToGenerate, hdWalletConfig.addressesToGenerate);
            expanded_patterns.insert(expanded_patterns.end(), exp.begin(), exp.end());
        }

        std::vector<std::vector<uint32_t>> paths = get_all_derivation_paths(expanded_patterns, hdWalletConfig.accountsToGenerate, hdWalletConfig.addressesToGenerate);
        std::set<std::vector<uint32_t>, PathCompare> oPath(paths.begin(), paths.end());
        print_paths(oPath);
    }

    uint64_t mnemonicsPerSecond = 0;
    utils::Timer t;
    while (t.elapsedS() <= 1)
    {
        ++mnemonicsPerSecond;
        // Specify entropy length for mnemonic (128 bits for 12 words, 256 bits for 24 words)
        std::vector<uint8_t> entropy = HDWallet::generateEntropy(BIP39_ENTROPY_LEN_128);

        std::string mnemonic = HDWallet::generateMnemonic(entropy);
//        std::cout << "Generated mnemonic: " << mnemonic << '\n';
    }

    std::cerr << "mnemonicsPerSecond: " << mnemonicsPerSecond << '\n';

    return 0;
}