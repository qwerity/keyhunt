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
    void init2(const std::vector<std::vector<uint32_t>>& derivationPaths, uint32_t accountsToGenerate, uint32_t addressesToGenerate, uint32_t publicKeyCompressionTypeToCheck, uint32_t gridSize, uint32_t blockSize) const;
    void generatePublicKeysForMnemonics(const uint8_t* mnemonics, uint32_t numMnemonics) const;

    [[nodiscard]] uint32_t getMnemonicsPerIteration() const;

    void getPublicKeys(std::vector<extended_public_key_t>& publicKeys) const;

private:
    struct Impl;
    std::unique_ptr<Impl> mImpl;
};
