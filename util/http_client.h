#pragma once

#include <boost/beast/http/status.hpp>

#include "config.h"

#include <vector>

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;

constexpr uint32_t http11Version{11}; // HTTP1.1 version

class HttpClient
{
public:
    /** connectTimeoutSec and readWriteTimeoutSec: use defaults 60/45 if negative. */
    explicit HttpClient(const ServerConfig& config, int connectTimeoutSec = -1, int readWriteTimeoutSec = -1);
    ~HttpClient();

    HttpClient(const HttpClient& other) = delete;
    HttpClient& operator=(const HttpClient& other) = delete;

    [[nodiscard]]  std::string hostConfig() const;

    http::status generateToken(std::string& token) const;
    [[nodiscard]] bool hostAlive() const;
    /** Get one number (GET /get_number?count=1). Response: {"numbers": [N]} */
    http::status getXPartNumber(uint32_t& number) const;
    /** Get up to count numbers (1-1000). Response: {"numbers": [N1, N2, ...]} */
    http::status getXPartNumbers(std::vector<uint32_t>& numbers, uint32_t count = 1) const;
    [[nodiscard]] bool markXPartDone(const uint32_t number) const;
    /** Mark multiple numbers done. Body: {"nums": [N1, N2, ...]}. Response: {"success": true, "marked": [...]} */
    [[nodiscard]] bool markXPartDone(const std::vector<uint32_t>& numbers) const;
    /** POST /set_found — отметка ключа как найденного по координатам x, y. Body: {"x": N, "y": M} */
    [[nodiscard]] bool setXPartFound(uint32_t x, uint32_t y) const;

private:
    struct Impl;
    std::unique_ptr<Impl> mImpl;
};