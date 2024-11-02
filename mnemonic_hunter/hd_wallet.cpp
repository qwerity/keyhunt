#include "hd_wallet.h"
#include "cuda/secp256k1_v2/bip32.cuh"

#include <wally_bip32.h>
#include <wally_bip39.h>

#include <random>

#include <boost/log/trivial.hpp>

constexpr char accountPlaceholder[] = "acc";
constexpr char addressPlaceholder[] = "addr";

struct HDWallet::Impl
{
    std::shared_ptr<GlobalContext> gContext;

    explicit Impl(const std::shared_ptr<GlobalContext>& context) : gContext(context) {}
    ~Impl() = default;

    void generateMasterKeys(std::vector<std::vector<uint32_t>>& mnemonics)
    {

    }
    void init()
    {

    }

};

HDWallet::HDWallet(const std::shared_ptr<GlobalContext>& context) : mImpl(std::make_unique<Impl>(context)) {}
HDWallet::~HDWallet() = default;

HDWallet::HDWallet(HDWallet&& rhs) noexcept = default;
HDWallet& HDWallet::operator=(HDWallet &&rhs) noexcept = default;

// Function to generate entropy of desired bit length (multiples of 32)
std::vector<uint8_t> HDWallet::generateEntropy(size_t bytes)
{
    // Ensure bytes is a multiple of 32
    if ((bytes * 8) % 32 != 0)
    {
        BOOST_LOG_TRIVIAL(error) << "Entropy bit length must be a multiple of 32.";
        return {};
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
std::string HDWallet::generateMnemonic(const std::vector<uint8_t>& entropy)
{
    char* mnemonic = nullptr;

    // Convert entropy to BIP39 mnemonic
    if (bip39_mnemonic_from_bytes(nullptr, entropy.data(), entropy.size(), &mnemonic) != WALLY_OK)
    {
        BOOST_LOG_TRIVIAL(error) << "Failed to generate mnemonic from entropy.";
        return {};
    }

    std::string result(mnemonic);
    wally_free_string(mnemonic); // Free allocated mnemonic string

    return result;
}