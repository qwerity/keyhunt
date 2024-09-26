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

    // Function to make the HTTP GET request
    http::status getNumber(uint32_t& number);

private:
    struct Impl;
    std::unique_ptr<Impl> mImpl;
};