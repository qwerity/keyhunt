#pragma once

#include "hd_wallet_defines.h"
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

    void init(HDWalletGenerationMode generationMode, const std::vector<std::vector<uint32_t>>& derivationPaths, uint32_t accountsToGenerate, uint32_t addressesToGenerate, uint32_t publicKeyCompressionTypeToCheck, uint32_t gridSize, uint32_t blockSize) const;

    void masterKeysFromMnemonics(const std::vector<uint8_t>& mnemonics) const;
    void searchPublicHashFromMnemonicsMasterKeys() const;

    void searchPublicHashFromMnemonics(const uint8_t* mnemonics, uint32_t mnemonicsNumber) const;
    void searchPublicHashFromMnemonicsMasterKeys(const std::vector<HDExtendedPrivateKey>& masterKeys) const;

    [[nodiscard]] uint32_t getMaxDataPerIteration() const;

    void getPublicKeys(std::vector<HDExtendedPublicKey>& publicKeys) const;

private:
    struct Impl;
    std::unique_ptr<Impl> mImpl;
};
