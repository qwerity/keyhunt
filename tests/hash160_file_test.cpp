#define CATCH_CONFIG_MAIN
#include <catch2/catch_all.hpp>

#include "util/utils.h"
#include "cuda/defines.h"
#include "cuda/hash160_lookup.cuh"

#include <iostream>
#include <format>
#include <iomanip>
#include <sstream>

// Функция для конвертации hex строки в hash160 с учетом byte order
hash160 hexStringToHash160(const std::string& hexStr, bool swapBytes = false)
{
    hash160 h;
    if (hexStr.length() != 40)
    {
        return h;
    }
    
    // Читаем hex строку как байты
    for (uint32_t i = 0; i < 5; ++i)
    {
        std::string hexByteStr(hexStr.substr(i * 8, 8));
        uint32_t value = std::stoul(hexByteStr, nullptr, 16);
        
        if (swapBytes)
        {
            // Меняем порядок байт (big-endian -> little-endian)
            h.h[i] = ((value & 0x000000FF) << 24) |
                     ((value & 0x0000FF00) << 8) |
                     ((value & 0x00FF0000) >> 8) |
                     ((value & 0xFF000000) >> 24);
        }
        else
        {
            h.h[i] = value;
        }
    }
    
    return h;
}

// Функция для конвертации hash160 в hex строку
std::string hash160ToHexString(const hash160& h, bool swapBytes = false)
{
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    
    for (int i = 0; i < 5; ++i)
    {
        uint32_t value = h.h[i];
        if (swapBytes)
        {
            value = ((value & 0x000000FF) << 24) |
                    ((value & 0x0000FF00) << 8) |
                    ((value & 0x00FF0000) >> 8) |
                    ((value & 0xFF000000) >> 24);
        }
        ss << std::setw(8) << value;
    }
    
    return ss.str();
}

TEST_CASE("Test hash160 file loading and search", "[hash160]")
{
    // Путь к файлу с hash160 целями
    const std::string hash160File = "./bitcoin-2016_6.h160.bin";
    
    // Хеш для поиска
    const std::string targetHashHex = "65c49a515584681366cdbac2ccfb985f4be1427a";
    
    Hash160Set hash160Targets;
    
    // Загружаем hash160 цели из файла
    std::cout << "Loading hash160 targets from: " << hash160File << std::endl;
    utils::readHash160Targets({hash160File}, hash160Targets);
    
    REQUIRE_FALSE(hash160Targets.empty());
    std::cout << std::format("Loaded {} hash160 targets\n", hash160Targets.size());
    
    // Пробуем разные варианты конвертации
    std::cout << "\nSearching for hash: " << targetHashHex << std::endl;
    
    // Вариант 1: используем toHash160 (читает как big-endian слова)
    hash160 targetHash1 = utils::toHash160(targetHashHex);
    std::cout << "Method 1 (toHash160): ";
    for (int i = 0; i < 5; ++i)
    {
        std::cout << std::format("{:08x} ", targetHash1.h[i]);
    }
    std::cout << std::endl;
    
    bool found1 = hash160Targets.contains(targetHash1);
    std::cout << "  Result: " << (found1 ? "FOUND" : "NOT FOUND") << std::endl;
    
    // Вариант 2: конвертируем с swap bytes (big-endian -> little-endian)
    hash160 targetHash2 = hexStringToHash160(targetHashHex, true);
    std::cout << "Method 2 (with byte swap): ";
    for (int i = 0; i < 5; ++i)
    {
        std::cout << std::format("{:08x} ", targetHash2.h[i]);
    }
    std::cout << std::endl;
    
    bool found2 = hash160Targets.contains(targetHash2);
    std::cout << "  Result: " << (found2 ? "FOUND" : "NOT FOUND") << std::endl;
    
    // Вариант 3: читаем hex строку как байты напрямую (little-endian байты в словах)
    // Hex строка представляет байты в big-endian порядке: e4 82 94 ee ...
    // Нужно читать их как байты и упаковывать в uint32_t слова в little-endian порядке
    hash160 targetHash3;
    const char* hexStr = targetHashHex.c_str();
    for (int wordIdx = 0; wordIdx < 5; ++wordIdx)
    {
        uint32_t word = 0;
        for (int byteIdx = 0; byteIdx < 4; ++byteIdx)
        {
            int hexPos = (wordIdx * 4 + byteIdx) * 2;
            std::string byteStr(hexStr + hexPos, 2);
            uint8_t byte = static_cast<uint8_t>(std::stoul(byteStr, nullptr, 16));
            // Упаковываем байты в little-endian порядке (младший байт первым)
            word |= (static_cast<uint32_t>(byte) << (byteIdx * 8));
        }
        targetHash3.h[wordIdx] = word;
    }
    std::cout << "Method 3 (byte-by-byte little-endian): ";
    for (int i = 0; i < 5; ++i)
    {
        std::cout << std::format("{:08x} ", targetHash3.h[i]);
    }
    std::cout << std::endl;
    
    bool found3 = hash160Targets.contains(targetHash3);
    std::cout << "  Result: " << (found3 ? "FOUND" : "NOT FOUND") << std::endl;
    
    bool found = found1 || found2 || found3;
    
    if (!found)
    {
        std::cout << "\n✗ Hash NOT FOUND with any method!" << std::endl;
        
        // Показываем несколько примеров хешей из файла для сравнения
        std::cout << "\nFirst 5 hashes in file (for comparison):" << std::endl;
        int count = 0;
        for (const auto& h : hash160Targets)
        {
            if (count++ < 5)
            {
                std::string hexStr = utils::toHex(h.h, 5);
                std::cout << "  " << hexStr << std::endl;
            }
        }
    }
    else
    {
        std::cout << "\n✓ Hash FOUND!" << std::endl;
    }
    
    REQUIRE(found);
}
