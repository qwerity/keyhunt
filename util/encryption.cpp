#include "crypto_util.h"
#include "utils.h"

#include <openssl/evp.h>
#include <openssl/aes.h>

namespace crypto
{
    bool aes_gcm_enc(const std::string& plaintext, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv, std::vector<unsigned char>& tag, std::vector<unsigned char>& ciphertext)
    {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) { return false; }
        utils::ScopeOutRunner scopeOutRunner([&ctx]() { EVP_CIPHER_CTX_free(ctx); });

        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key.data(), iv.data()) != 1)
        {
            return false;
        }

        int len;
        ciphertext.resize(plaintext.size() + AES_BLOCK_SIZE);
        if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size()) != 1)
        {
            return false;
        }
        int ciphertext_len = len;

        if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1)
        {
            return false;
        }
        ciphertext_len += len;
        ciphertext.resize(ciphertext_len);

        tag.resize(16);
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag.size(), tag.data()) != 1)
        {
            return false;
        }

        return true;
    }

    bool aes_gcm_dec(const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv, const std::vector<unsigned char>& tag, std::string& plaintext)
    {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) { return false; }
        utils::ScopeOutRunner scopeOutRunner([&ctx]() { EVP_CIPHER_CTX_free(ctx); });

        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key.data(), iv.data()) != 1)
        {
            return false;
        }

        std::vector<unsigned char> plaintext_buffer(ciphertext.size());
        int len;
        if (EVP_DecryptUpdate(ctx, plaintext_buffer.data(), &len, ciphertext.data(), ciphertext.size()) != 1)
        {
            return false;
        }
        int plaintext_len = len;

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag.size(), const_cast<unsigned char*>(tag.data())) != 1)
        {
            return false;
        }

        if (EVP_DecryptFinal_ex(ctx, plaintext_buffer.data() + len, &len) != 1)
        {
            return false;
        }
        plaintext_len += len;

        plaintext.assign(reinterpret_cast<char*>(plaintext_buffer.data()), plaintext_len);
        return true;
    }

    AES::AES(const std::string& hexKey, const std::string& iv) : mKey(2 * AES_BLOCK_SIZE), mIV(ivSize)
    {
        mKey = utils::fromHex(hexKey);
        mIV = utils::fromHex(iv);
    }

    bool AES::encrypt(const std::string& plaintext, std::vector<unsigned char>& tag, std::vector<unsigned char>& ciphertext) const
    {
        return aes_gcm_enc(plaintext, mKey, mIV, tag, ciphertext);
    }

    bool AES::decrypt(const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char>& tag, std::string& plaintext) const
    {
        return aes_gcm_dec(ciphertext, mKey, mIV, tag, plaintext);
    }
}