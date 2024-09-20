#include "utils.h"
#include "secp256k1.h"

#include "cuda/defines.cuh"

#include <cstdio>
#include <string>
#include <fstream>
#include <utility>
#include <vector>
#include <algorithm>
#include <iomanip>

#include <boost/log/utility/setup.hpp>

#ifdef _WIN32
    #include<windows.h>
#else
    #include<unistd.h>
    #include<sys/stat.h>
    #include<sys/time.h>
#endif

namespace utils
{
    uint64_t getSystemTime()
    {
#ifdef _WIN32
        return GetTickCount64();
#else
        timeval t{};
        gettimeofday(&t, nullptr);
        return static_cast<uint64_t>(t.tv_sec) * 1000 + t.tv_usec / 1000;
#endif
    }

    Timer::Timer()
    {
        _startTime = 0;
    }

    void Timer::start()
    {
        _startTime = getSystemTime();
    }

    uint64_t Timer::getTime() const
    {
        return getSystemTime() - _startTime;
    }

    std::string formatThousands(const uint64_t x)
    {
        std::string s = std::to_string(x);

        const auto len = static_cast<int>(s.length());
        if (const int numCommas = (len - 1) / 3; numCommas == 0)
        {
            return s;
        }

        std::string result;
        int count = ((len % 3) == 0) ? 0 : (3 - (len % 3));
        for (int i = 0; i < len; i++)
        {
            result += s[i];
            if (count++ == 2 && i < len - 1)
            {
                result += ",";
                count = 0;
            }
        }
        return result;
    }

    uint32_t parseUInt32(std::string s)
    {
        return static_cast<uint32_t>(parseUInt64(std::move(s)));
    }

    uint64_t parseUInt64(std::string s)
    {
        uint64_t val = 0;
        bool isHex = false;
        if (s[0] == '0' && s[1] == 'x')
        {
            isHex = true;
            s = s.substr(2);
        }
        if (s[s.length() - 1] == 'h')
        {
            isHex = true;
            s = s.substr(0, s.length() - 1);
        }
        if (isHex)
        {
            if (std::sscanf(s.c_str(), "%I64u", &val) != 1)
            {
                throw std::string("Expected an integer");
            }
        } else
        {
            if (std::sscanf(s.c_str(), "%I64u", &val) != 1)
            {
                throw std::string("Expected an integer");
            }
        }
        return val;
    }

    bool isHex(const std::string &s)
    {
        return std::ranges::all_of(s, [](const char c) { return std::isxdigit(c); });
    }

    std::string formatSeconds(const uint32_t seconds)
    {
        const uint32_t days = seconds / 86400;
        const uint32_t hours = (seconds % 86400) / 3600;
        const uint32_t minutes = (seconds % 3600) / 60;
        const uint32_t sec = seconds % 60;

        if (days > 0)
        {
            return utils::format("%d:%02d:%02d:%02d", days, hours, minutes, sec);
        }

        return utils::format("%02d:%02d:%02d", hours, minutes, sec);
    }

    long getFileSize(const std::string &fileName)
    {
        FILE *fp = fopen(fileName.c_str(), "rb");
        if (fp == nullptr)
        {
            return -1;
        }
        fseek(fp, 0, SEEK_END);
        long pos = ftell(fp);
        fclose(fp);
        return pos;
    }

    bool appendToFile(const std::string &fileName, const std::string &s)
    {
        std::ofstream outFile;
        bool newline = false;
        if (getFileSize(fileName) > 0)
        {
            newline = true;
        }
        outFile.open(fileName.c_str(), std::ios::app);
        if (!outFile.is_open())
        {
            return false;
        }
        // Add newline following previous line
        if (newline)
        {
            outFile << std::endl;
        }
        outFile << s;
        return true;
    }

    std::string convertToHexString(const uint32_t* arr, const uint32_t size)
    {
        std::stringstream ss;
        // Iterate through each byte of the array
        for (uint32_t i = 0; i < size; ++i)
        {
            const auto *bytePtr = reinterpret_cast<const uint8_t *>(&arr[i]);
            for (std::size_t j = 0; j < sizeof(uint32_t); ++j)
            {
                ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(bytePtr[j]);
            }
        }
        return ss.str();
    }

    void initLogging([[maybe_unused]] const std::string& logFile)
    {
        boost::log::add_console_log(std::cerr, boost::log::keywords::auto_flush = true);
        // boost::log::add_console_log(std::cerr, boost::log::keywords::format = "[%TimeStamp%] [%ThreadID%]: %Message%");

        // // Setting up a file logger
        // boost::log::add_file_log(logFile, boost::log::keywords::auto_flush = true);
        // boost::log::add_file_log(logFile, boost::log::keywords::format = "[%TimeStamp%] [%ThreadID%]: %Message%");

        // Add attributes like timestamp and thread id
        // boost::log::add_common_attributes();

        // boost::log::core::get()->set_filter(
        //     boost::log::trivial::severity > boost::log::trivial::fatal
        // );
    }

    std::vector<secp256k1::uint256> generateRandomPrivateKeys(const uint32_t keysNumberToGenerate)
    {
        std::vector<secp256k1::uint256> privateKeys;

        constexpr uint32_t testKey[8]{0x3d52d30a, 0x720debe8, 0x4fc939bb, 0xf806a1de, 0x3cee918e, 0x99fafd29, 0xe9a2e3fa, 0x2c478ee7};
        privateKeys.emplace_back(testKey, secp256k1::uint256::BigEndian);
        privateKeys.emplace_back(std::string("0100000000000000000000000000000000000000000000000000000000000000"));
        privateKeys.emplace_back(std::string("0100000000000000000000000000000000000000000000000000000000000200"));
        privateKeys.emplace_back(std::string("d7ae6ac85e67dfe75b3a42c6453abed4bb34a26d2988481fc134b2d845976a56"));
        privateKeys.emplace_back(std::string{"f71485d0bff28cf3a9f1b6c2b65b03729f42f9818fb497c6fae7268bb124f263"});

        std::generate_n(std::back_inserter(privateKeys), keysNumberToGenerate, secp256k1::generatePrivateKey);
        return privateKeys;
    }

    hash160 toHash160(const std::string& hexString)
    {
        hash160 hash;
        if (hexString.length() != sizeof(hash160) * 2)
        {
            fprintf(stderr,  "RIPEMD-160 hex string must be exactly 40 characters long!\n");
            return hash;
        }

        for (int i = 0; i < 5; ++i)
        {
            std::stringstream ss;
            ss << std::hex << hexString.substr(i * 8, 8);
            ss >> hash.h[i];
        }

        return hash;
    }

    // Function to convert 20 bytes (40 hex characters) to uint32_t[5]
    hash160 hexToHash160(const char *data)
    {
        hash160 hash;
        for (size_t i = 0; i < 5; ++i)
        {
            std::string hex_str(data + i * 8, 8);  // Create a string from 8 characters
            hash.h[i] = std::stoul(hex_str, nullptr, 16);
        }

        return std::move(hash);
    }
}
