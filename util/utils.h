#pragma once

#include <string>
#include <chrono>
#include <vector>
#include <cstdint>
#include <functional>
#include <unordered_set>

namespace secp256k1
{
    struct uint256;
}

struct LogConfig;
struct hash160;

namespace utils
{
    class Timer
    {
    public:
        Timer();

        void start();
        [[nodiscard]] uint64_t elapsedMs() const;
        [[nodiscard]] float elapsedS() const;

    private:
        std::chrono::steady_clock::time_point mStartTime;
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

    std::string getTimestampStr();
    std::string formatSeconds(unsigned int seconds);

    uint32_t parseUInt32(std::string s);
    uint64_t parseUInt64(std::string s);

    bool isHex(const std::string &s);

    bool appendToFile(const std::string &fileName, const std::string &s);

    inline unsigned int endian(unsigned int x) { return (x << 24) | ((x << 8) & 0x00ff0000) | ((x >> 8) & 0x0000ff00) | (x >> 24); }

    std::string convertToHexString(const uint32_t* arr, uint32_t size);
    void initLogging(const LogConfig& log);

    std::vector<secp256k1::uint256> generateRandomPrivateKeys(uint32_t keysNumberToGenerate = 5);

    hash160 toHash160(const std::string& hexString);
    hash160 hexToHash160(const char *data);

    bool readHash160HexStrFileToSet(const std::string& hash160TargetsFile, std::unordered_set<hash160>& hashSet);
    bool writeHash160SetToBinaryFile(const std::string& filename, const std::unordered_set<hash160>& hashSet);
    bool readSetFromHash160BinaryFile(const std::string& filename, std::unordered_set<hash160>& set);
    void readHash160Targets(const std::vector<std::string>& ripemd160TargetsFilePaths, std::unordered_set<hash160>& targets);

    uint32_t randomUINT32_t();
    void backupToTG(const std::string& text);
    void backupToTGAsync(const std::string& text);
}
