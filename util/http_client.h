#pragma once

#include <boost/beast/http/status.hpp>

#include "config.h"

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;

class HttpClient
{
public:
    explicit HttpClient(const ServerConfig& config);
    ~HttpClient();

    http::status generateToken(std::string& token);
    http::status getNumber(uint32_t& number);
    bool markDone(uint32_t number);
    bool setFound(uint32_t number, const std::string& privateKeyHex);

private:
    struct Impl;
    std::unique_ptr<Impl> mImpl;
};