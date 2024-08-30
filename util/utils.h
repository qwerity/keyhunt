#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <functional>

namespace utils
{
    class Timer
    {
    public:
        Timer();

        void start();
        uint64_t getTime() const;

    private:
        uint64_t _startTime;
    };

    class ScopeOutRunner
    {
    public:
        explicit ScopeOutRunner(std::function<void()> f, bool enabled = true) : mf(std::move(f)), mEnabled(enabled) {};
        ~ScopeOutRunner()
        {
            if(mEnabled && mf)
                mf();
        }

        void setEnabled(bool e) { mEnabled = e; };
        void enable() { setEnabled(true); }
        void disable() { setEnabled(false); }

    private:
        std::function<void()> mf{nullptr};
        bool mEnabled;
    };

    uint64_t getSystemTime();

    void sleep(int seconds);

    std::string formatThousands(uint64_t x);
    std::string formatSeconds(unsigned int seconds);

    uint32_t parseUInt32(std::string s);
    uint64_t parseUInt64(std::string s);

    bool isHex(const std::string &s);

    bool appendToFile(const std::string &fileName, const std::string &s);

    bool readLinesFromStream(std::istream &in, std::vector<std::string> &lines);
    bool readLinesFromStream(const std::string &fileName, std::vector<std::string> &lines);

    std::string format(const char *formatStr, double value);
    std::string format(uint32_t value);
    std::string format(uint64_t value);
    std::string format(int value);

    void removeNewline(std::string &s);

    unsigned int endian(unsigned int x);

    std::string toLower(const std::string &s);

    std::string trim(const std::string &s, char c = ' ');
}
