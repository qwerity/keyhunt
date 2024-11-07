#pragma once

#include "secp256k1_v2/bip32.cuh"
#include <vector>
#include <memory>

class CUHDWallet
{
public:
    CUHDWallet();
    ~CUHDWallet();

    CUHDWallet(const CUHDWallet&) = delete;
    CUHDWallet& operator=(const CUHDWallet&) = delete;

    CUHDWallet(CUHDWallet&& rhs) noexcept;
    CUHDWallet& operator=(CUHDWallet&& rhs) noexcept;

    void init(const std::vector<std::vector<uint32_t>>& derivationPaths, uint32_t publicKeyCompressionTypeToCheck, uint32_t gridSize = 0, uint32_t blockSize = 0) const;
    void generatePublicKeysForMnemonics(const uint8_t* mnemonics, uint32_t numMnemonics) const;
    void generatePublicKeysForMnemonicsThrust(const uint8_t* mnemonics, uint32_t mnemonicsNumber) const;

    [[nodiscard]] uint32_t getMnemonicsPerIteration() const;

    void getPublicKeys(std::vector<extended_public_key_t>& publicKeys) const;

private:
    struct Impl;
    std::unique_ptr<Impl> mImpl;
};
