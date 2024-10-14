#pragma once

#include <boost/beast/http/status.hpp>

#include "config.h"

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;

constexpr uint32_t http11Version{11}; // HTTP1.1 version

class HttpClient
{
public:
    explicit HttpClient(const ServerConfig& config);
    ~HttpClient();

    HttpClient(const HttpClient& other) = delete;
    HttpClient& operator=(const HttpClient& other) = delete;

    [[nodiscard]]  std::string hostConfig() const;

    http::status generateToken(std::string& token) const;
    [[nodiscard]] bool hostAlive() const;
    http::status getNumber(uint32_t& number) const;
    [[nodiscard]] bool markDone(uint32_t number) const;
    [[nodiscard]] bool setFound(uint32_t number, const std::string& privateKeyHex) const;

private:
    struct Impl;
    std::unique_ptr<Impl> mImpl;
};