#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <functional>
#include <unordered_set>

struct LogConfig;

namespace secp256k1
{
    struct uint256;
}

struct hash160;

namespace utils
{
    class Timer
    {
    public:
        Timer();

        void start();
        [[nodiscard]] uint64_t getTime() const;

    private:
        uint64_t _startTime{0};
    };

    class ScopeOutRunner
    {
    public:
        explicit ScopeOutRunner(std::function<void()> f, bool enabled = true) : mf(std::move(f)), mEnabled(enabled) {};
        ~ScopeOutRunner()
        {
            if(mEnabled && mf) { mf(); }
        }

        void setEnabled(bool e) { mEnabled = e; };
        void enable() { setEnabled(true); }
        void disable() { setEnabled(false); }

    private:
        std::function<void()> mf{nullptr};
        bool mEnabled;
    };

    uint64_t getSystemTime();

    std::string formatThousands(uint64_t x);
    std::string formatSeconds(unsigned int seconds);

    uint32_t parseUInt32(std::string s);
    uint64_t parseUInt64(std::string s);

    bool isHex(const std::string &s);

    bool appendToFile(const std::string &fileName, const std::string &s);

    template <typename T>
    std::string format(T value, std::enable_if_t<std::is_integral_v<T>>* = nullptr)
    {
        return std::to_string(value);
    }

    template <typename... Args>
    std::string format(const std::string& formatStr, Args&&... args)
    {
        if (formatStr.empty())
            return {};

        // First, calculate the size of the required buffer
        const int size = std::snprintf(nullptr, 0, formatStr.c_str(), args...);

        // Create a buffer large enough to hold the formatted string
        std::vector<char> buf(size + 1);  // +1 for null terminator

        // Format the string into the buffer
        std::snprintf(buf.data(), buf.size(), formatStr.c_str(), args...);

        // Return the result as a std::string
        return buf.data();
    }

    inline unsigned int endian(unsigned int x) { return (x << 24) | ((x << 8) & 0x00ff0000) | ((x >> 8) & 0x0000ff00) | (x >> 24); }

    std::string convertToHexString(const uint32_t* arr, uint32_t size);
    void initLogging(const LogConfig& log);

    std::vector<secp256k1::uint256> generateRandomPrivateKeys(uint32_t keysNumberToGenerate = 5);

    hash160 toHash160(const std::string& hexString);
    hash160 hexToHash160(const char *data);
}
