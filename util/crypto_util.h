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
        void get(unsigned char *buf, int len);

    private:
        void reseed();

        uint32_t _state[16]{};
        uint32_t _counter{};
    };

    bool aes_gcm_enc(const std::string& plaintext, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv, std::vector<unsigned char>& tag, std::vector<unsigned char>& ciphertext);
    bool aes_gcm_dec(const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv, const std::vector<unsigned char>& tag, std::string& plaintext);

    class AES
    {
    public:
        constexpr static uint32_t tagSize{16};
        constexpr static uint32_t ivSize{12};
        constexpr static uint32_t aesKeyLength{256};

        AES(const std::string& hexKey, const std::string& iv);

        bool encrypt(const std::string& plaintext, std::vector<unsigned char>& tag, std::vector<unsigned char>& ciphertext) const;
        bool decrypt(const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char>& tag, std::string& plaintext) const;

    private:
        std::vector<unsigned char> mKey;
        std::vector<unsigned char> mIV;
    };

    void ripemd160(uint32_t *msg, uint32_t *digest);
    void sha256Init(uint32_t *digest);
    void sha256(const uint32_t *msg, uint32_t *digest);
    uint32_t checksum(const uint32_t *hash);
}
