#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace crypto
{
    class rng
    {
    public:
        rng();
        void get(uint8_t *buf, int len);

    private:
        void reseed();

        uint32_t _state[16]{};
        uint32_t _counter{};
    };

    bool aes_gcm_enc(const std::string& plaintext, const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv, std::vector<uint8_t>& tag, std::vector<uint8_t>& ciphertext);
    bool aes_gcm_dec(const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv, const std::vector<uint8_t>& tag, std::string& plaintext);

    class AES
    {
    public:
        constexpr static uint32_t tagSize{16};
        constexpr static uint32_t ivSize{12};
        constexpr static uint32_t aesKeyLength{256};

        AES(const std::string& hexKey, const std::string& iv);

        bool encrypt(const std::string& plaintext, std::vector<uint8_t>& tag, std::vector<uint8_t>& ciphertext) const;
        bool decrypt(const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& tag, std::string& plaintext) const;

    private:
        std::vector<uint8_t> mKey;
        std::vector<uint8_t> mIV;
    };

    void ripemd160(uint32_t *msg, uint32_t *digest);
    void sha256Init(uint32_t *digest);
    void sha256(const uint32_t *msg, uint32_t *digest);
    uint32_t checksum(const uint32_t *hash);

    // Generate private key using Android KeyStore-like algorithm
    void generatePrivateKey(int32_t x, int32_t y, uint8_t* output);
    // Generate private key using the SHA1PRNG flow equivalent to CUDA generatePrivateKeyBase
    void generatePrivateKey2(int32_t x, int32_t y, uint8_t* output);
}
