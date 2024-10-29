#include <wally_bip39.h>

#include "util/utils.h"

#include <iostream>
#include <vector>
#include <random>

using namespace std;

// Function to generate entropy of desired bit length (multiples of 32)
std::vector<uint8_t> generateEntropy(size_t bytes)
{
    // Ensure bytes is a multiple of 32
    if ((bytes * 8) % 32 != 0)
    {
        throw std::invalid_argument("Entropy bit length must be a multiple of 32.");
    }

    std::vector<uint8_t> entropy(bytes);

    std::random_device rd;
    std::mt19937_64 rng(rd()); // 64-bit Mersenne Twister RNG

    for (size_t i = 0; i < bytes; i += 8)
    {
        // Generate 64-bit random value
        uint64_t randomValue = rng();
        for (size_t j = 0; j < 8 && i + j < bytes; ++j)
        {
            entropy[i + j] = (randomValue >> (8 * j)) & 0xFF;
        }
    }

    return entropy;
}

// Function to convert entropy to a BIP39 mnemonic
std::string generateMnemonic(const std::vector<uint8_t>& entropy)
{
    char* mnemonic = nullptr;

    // Convert entropy to BIP39 mnemonic
    if (bip39_mnemonic_from_bytes(nullptr, entropy.data(), entropy.size(), &mnemonic) != WALLY_OK)
    {
        throw std::runtime_error("Failed to generate mnemonic from entropy.");
    }

    std::string result(mnemonic);
    wally_free_string(mnemonic); // Free allocated mnemonic string

    return result;
}

int main()
{
    constexpr int wallyInitFlags{0};

    // Initialize the Wally core library
    if (wally_init(wallyInitFlags) != WALLY_OK)
    {
        std::cerr << "Failed to initialize Wally\n";
        return 1;
    }
    utils::ScopeOutRunner outRunner([]() { wally_cleanup(wallyInitFlags); });

    uint64_t mnemonicsPerSecond = 0;
    utils::Timer t;
    while(t.elapsedS() <= 1)
    {
        ++mnemonicsPerSecond;
        // Specify entropy length for mnemonic (128 bits for 12 words, 256 bits for 24 words)
        std::vector<uint8_t> entropy = generateEntropy(BIP39_ENTROPY_LEN_128);

        std::string mnemonic = generateMnemonic(entropy);
//        std::cout << "Generated mnemonic: " << mnemonic << '\n';
    }

    std::cerr << "mnemonicsPerSecond: " << mnemonicsPerSecond << '\n';

    return 0;
}