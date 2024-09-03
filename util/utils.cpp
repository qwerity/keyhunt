#include "utils.h"

#include<cstdio>
#include<string>
#include<fstream>
#include <utility>
#include<vector>
#include<algorithm>

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

    void sleep(int seconds)
    {
#ifdef _WIN32
        Sleep(seconds * 1000);
#else
        ::sleep(seconds);
#endif
    }

    std::string formatThousands(const uint64_t x)
    {
        char buf[32] = "";
        sprintf(buf, "%lud", x);
        std::string s(buf);
        auto len = static_cast<int>(s.length());
        if (int numCommas = (len - 1) / 3; numCommas == 0)
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
            if (sscanf(s.c_str(), "%lux", &val) != 1)
            {
                throw std::string("Expected an integer");
            }
        } else
        {
            if (sscanf(s.c_str(), "%lud", &val) != 1)
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

    std::string formatSeconds(unsigned int seconds)
    {
        unsigned int days = seconds / 86400;
        unsigned int hours = (seconds % 86400) / 3600;
        unsigned int minutes = (seconds % 3600) / 60;
        unsigned int sec = seconds % 60;

        if (days > 0)
        {
            return std::format("%d:%02d:%02d:%02d", days, hours, minutes, sec);
        }

        return std::format("%02d:%02d:%02d", hours, minutes, sec);
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

    bool readLinesFromStream(const std::string &fileName, std::vector<std::string> &lines)
    {
        std::ifstream inFile(fileName.c_str());
        if (!inFile.is_open())
        {
            return false;
        }
        return readLinesFromStream(inFile, lines);
    }

    bool readLinesFromStream(std::istream &in, std::vector<std::string> &lines)
    {
        std::string line;
        while (std::getline(in, line))
        {
            if (!line.empty())
            {
                lines.push_back(line);
            }
        }
        return true;
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

    void removeNewline(std::string &s)
    {
        const size_t len = s.length();
        int toRemove = 0;
        if (len >= 2)
        {
            if (s[len - 2] == '\r' || s[len - 2] == '\n')
            {
                toRemove++;
            }
        }
        if (len >= 1)
        {
            if (s[len - 1] == '\r' || s[len - 1] == '\n')
            {
                toRemove++;
            }
        }
        if (toRemove)
        {
            s.erase(len - toRemove);
        }
    }

    std::string toLower(const std::string &s)
    {
        std::string lowerCase = s;
        std::ranges::transform(lowerCase, lowerCase.begin(), ::tolower);
        return lowerCase;
    }

    std::string trim(const std::string &s, char c)
    {
        size_t left = s.find_first_not_of(c);
        size_t right = s.find_last_not_of(c);
        return s.substr(left, right - left + 1);
    }
}
