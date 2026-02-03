#include "util/utils.h"
#include "util/secp256k1.h"
#include "util/crypto_util.h"
#include "util/address_util.h"

#include <iostream>
#include <format>
#include <ranges>

int main()
{
    std::cout << "=== Hash160 for private key (X=1, Y=1) ===" << std::endl;
    
    // Генерируем приватный ключ для (1, 1)
    uint8_t privateKeyBytes[32] = {0};
    crypto::generatePrivateKey(1, 1, privateKeyBytes);
    
    std::cout << "Private key (hex): " << utils::toHex(privateKeyBytes, 32) << std::endl;
    
    // Конвертируем в secp256k1::uint256
    secp256k1::uint256 privateKey;
    for (int i = 0; i < 8; i++)
    {
        const int byte_idx = 7 - i;
        privateKey.v[i] = (static_cast<uint32_t>(privateKeyBytes[byte_idx * 4 + 0]) << 24) |
                          (static_cast<uint32_t>(privateKeyBytes[byte_idx * 4 + 1]) << 16) |
                          (static_cast<uint32_t>(privateKeyBytes[byte_idx * 4 + 2]) << 8) |
                          (static_cast<uint32_t>(privateKeyBytes[byte_idx * 4 + 3]));
    }
    
    // Вычисляем публичный ключ
    secp256k1::ecpoint publicKey = secp256k1::multiplyPoint(privateKey, secp256k1::G());
    
    uint32_t xWords[8]{};
    uint32_t yWords[8]{};
    publicKey.x.exportWords(xWords, 8, secp256k1::uint256::BigEndian);
    publicKey.y.exportWords(yWords, 8, secp256k1::uint256::BigEndian);
    
    // Вычисляем hash160
    uint32_t hash160Uncompressed[5]{};
    uint32_t hash160Compressed[5]{};
    Hash::hashPublicKey(xWords, yWords, hash160Uncompressed);
    Hash::hashPublicKeyCompressed(xWords, yWords, hash160Compressed);
    
    // Конвертируем в little-endian для вывода (как в структуре hash160)
    uint32_t hash160UncompressedLE[5]{};
    uint32_t hash160CompressedLE[5]{};
    std::ranges::transform(hash160Uncompressed, hash160UncompressedLE, utils::endian);
    std::ranges::transform(hash160Compressed, hash160CompressedLE, utils::endian);
    
    std::cout << "\n--- Hash160 in different formats ---" << std::endl;
    std::cout << "Uncompressed (little-endian words): " << utils::toHex(hash160UncompressedLE, 5) << std::endl;
    std::cout << "Compressed (little-endian words):   " << utils::toHex(hash160CompressedLE, 5) << std::endl;
    
    // Выводим также в формате big-endian слов
    std::cout << "\nUncompressed (big-endian words): " << utils::toHex(hash160Uncompressed, 5) << std::endl;
    std::cout << "Compressed (big-endian words):   " << utils::toHex(hash160Compressed, 5) << std::endl;
    
    // Выводим внутреннее представление
    std::cout << "\n--- Internal representation (uint32_t array) ---" << std::endl;
    std::cout << "Uncompressed LE: ";
    for (int i = 0; i < 5; ++i)
    {
        std::cout << std::format("{:08x} ", hash160UncompressedLE[i]);
    }
    std::cout << std::endl;
    
    std::cout << "Compressed LE:   ";
    for (int i = 0; i < 5; ++i)
    {
        std::cout << std::format("{:08x} ", hash160CompressedLE[i]);
    }
    std::cout << std::endl;
    
    std::cout << "\n--- Hash160 struct format (as stored in memory/file) ---" << std::endl;
    std::cout << "Uncompressed struct: " << utils::toHex(hash160UncompressedLE, 5) << std::endl;
    std::cout << "Compressed struct:   " << utils::toHex(hash160CompressedLE, 5) << std::endl;
    
    return 0;
}
