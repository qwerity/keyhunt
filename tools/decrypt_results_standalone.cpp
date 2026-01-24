// Standalone CPU-only версия decrypt_results без зависимостей от CUDA
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <sstream>
#include <iomanip>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <boost/iostreams/device/mapped_file.hpp>

// Константы из Config (hardcoded)
constexpr const char* AES_KEY = "CB4BBEDF03DA589798E997D86027DE755F33D226AEF90F395539DA4C08EF65B3";
constexpr const char* AES_IV = "7E1AAE9BAE242FC510D5619B";
constexpr uint32_t AES_TAG_SIZE = 16;

// Простая функция для конвертации hex строки в байты
std::vector<uint8_t> fromHex(const std::string& hexStr)
{
    if (hexStr.length() % 2 != 0)
    {
        throw std::runtime_error("Hex string length must be even");
    }

    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hexStr.length(); i += 2)
    {
        unsigned int byte;
        std::istringstream(hexStr.substr(i, 2)) >> std::hex >> byte;
        bytes.push_back(static_cast<uint8_t>(byte));
    }
    return bytes;
}

// Класс AES для дешифрования
class AES
{
public:
    AES(const std::string& hexKey, const std::string& hexIV)
    {
        mKey = fromHex(hexKey);
        mIV = fromHex(hexIV);
    }

    bool decrypt(const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& tag, std::string& plaintext) const
    {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx)
        {
            logOpenSSLErrors();
            return false;
        }

        // RAII для автоматической очистки
        struct ScopeGuard {
            EVP_CIPHER_CTX* ptr;
            ~ScopeGuard() { if (ptr) EVP_CIPHER_CTX_free(ptr); }
        } guard{ctx};

        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, mKey.data(), mIV.data()) != 1)
        {
            logOpenSSLErrors();
            return false;
        }

        std::vector<uint8_t> plaintext_buffer(ciphertext.size());
        int len;
        if (EVP_DecryptUpdate(ctx, plaintext_buffer.data(), &len, ciphertext.data(), static_cast<int>(ciphertext.size())) != 1)
        {
            logOpenSSLErrors();
            return false;
        }
        int plaintext_len = len;

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag.size()), const_cast<uint8_t*>(tag.data())) != 1)
        {
            logOpenSSLErrors();
            return false;
        }

        if (EVP_DecryptFinal_ex(ctx, plaintext_buffer.data() + len, &len) != 1)
        {
            logOpenSSLErrors();
            return false;
        }
        plaintext_len += len;

        plaintext.assign(reinterpret_cast<char*>(plaintext_buffer.data()), plaintext_len);
        return true;
    }

private:
    void logOpenSSLErrors() const
    {
        unsigned long errCode;
        std::ostringstream oss;

        while ((errCode = ERR_get_error()) != 0)
        {
            char errBuffer[256];
            ERR_error_string_n(errCode, errBuffer, sizeof(errBuffer));
            oss << "OpenSSL Error: " << errBuffer << '\n';
        }

        const std::string errString = oss.str();
        if (!errString.empty())
        {
            std::cerr << errString << std::endl;
        }
    }

    std::vector<uint8_t> mKey;
    std::vector<uint8_t> mIV;
};

// Функция для чтения и дешифрования результатов
bool readEncResults(const AES& aesEnc, const std::string& filename, std::vector<std::string>& results)
{
    try
    {
        boost::iostreams::mapped_file_source file;
        file.open(filename);

        if (!file.is_open())
        {
            std::cerr << "Error opening file: " << filename << std::endl;
            return false;
        }

        const char *data = file.data();
        const size_t fileSize = file.size();

        if (fileSize <= 0)
        {
            std::cerr << "Results file empty!" << std::endl;
            return false;
        }

        uint64_t readIndex{0};
        while (readIndex < fileSize)
        {
            if (readIndex + sizeof(uint32_t) > fileSize)
            {
                std::cerr << "Corrupted binary file [length] at position: " << readIndex << std::endl;
                return false;
            }

            uint32_t length{0};
            std::memcpy(&length, data + readIndex, sizeof(uint32_t));
            readIndex += sizeof(uint32_t);

            if (readIndex + AES_TAG_SIZE > fileSize)
            {
                std::cerr << "Corrupted binary file [tag] at position: " << readIndex << std::endl;
                return false;
            }

            std::vector<uint8_t> tag(AES_TAG_SIZE);
            std::memcpy(reinterpret_cast<char*>(tag.data()), data + readIndex, AES_TAG_SIZE);
            readIndex += AES_TAG_SIZE;

            const auto resultsEncSize = length - AES_TAG_SIZE;
            if (readIndex + resultsEncSize > fileSize)
            {
                std::cerr << "Corrupted binary file [resultsEnc] at position: " << readIndex << std::endl;
                return false;
            }

            std::vector<uint8_t> resultsEnc(resultsEncSize);
            std::memcpy(reinterpret_cast<char*>(resultsEnc.data()), data + readIndex, resultsEncSize);
            readIndex += resultsEncSize;

            std::string resultStr;
            if (aesEnc.decrypt(resultsEnc, tag, resultStr))
            {
                results.emplace_back(std::move(resultStr));
            }
            else
            {
                std::cerr << "Decryption fails [resultsEnc] at position: " << (readIndex - resultsEncSize) << std::endl;
                continue;
            }
        }

        file.close();
    }
    catch (const std::exception& e)
    {
        std::cerr << e.what() << std::endl;
        return false;
    }

    return true;
}

int main(int argc, char* argv[])
{
    if (argc != 2)
    {
        std::cerr << "Usage: " << argv[0] << " <filename>" << std::endl;
        return -1;
    }

    const std::string resultsFilePath = argv[1];

    const AES aesEnc(AES_KEY, AES_IV);

    std::vector<std::string> results;
    if (!readEncResults(aesEnc, resultsFilePath, results))
    {
        std::cerr << "Decrypting & Reading encrypted results fails!" << std::endl;
        return -1;
    }

    for (const auto& result : results)
    {
        std::cout << result << std::endl;
    }

    return 0;
}
