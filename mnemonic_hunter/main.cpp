#include <wally_bip39.h>

#include "util/utils.h"

#include <iostream>
#include <vector>
#include <random>

using namespace std;

int main()
{
    constexpr int wallyInitFlags{0};

    // Initialize the Wally core library
    if (wally_init(wallyInitFlags) != WALLY_OK)
    {
        std::cerr << "Failed to initialize Wally" << std::endl;
        return 1;
    }
    utils::ScopeOutRunner outRunner([](){ wally_cleanup(wallyInitFlags); });

    // Specify entropy length for mnemonic (128 bits for 12 words, 256 bits for 24 words)
    size_t entropy_length = BIP39_ENTROPY_LEN_128;

    // Buffer for the generated entropy
    std::vector<uint8_t> entropy(entropy_length);

    // Generate random entropy
    std::random_device rd;
    for (size_t i = 0; i < entropy_length; ++i)
    {
        entropy[i] = rd() & 0xFF;  // Generate secure random byte
    }

    // Buffer to hold the mnemonic phrase
    char* mnemonic = nullptr;

    // Generate the mnemonic from entropy
    if (bip39_mnemonic_from_bytes(nullptr, entropy.data(), entropy.size(), &mnemonic) == WALLY_OK)
    {
        std::cout << "Generated mnemonic: " << mnemonic << std::endl;
    }
    else
    {
        std::cerr << "Error generating mnemonic!" << std::endl;
    }

    // Free the mnemonic buffer
    wally_free_string(mnemonic);

    return 0;
}