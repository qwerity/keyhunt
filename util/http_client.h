#pragma once

#include <boost/asio/io_context.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/core/tcp_stream.hpp>
#include <boost/beast/core/flat_buffer.hpp>

#include "config.h"

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;

class HttpClient
{
public:
    explicit HttpClient(const ServerConfig& config);

    // Function to make the HTTP GET request
    http::status getNumber(uint32_t& number);

private:
    http::status get(const std::string& target, http::response<http::dynamic_body>& response);

private:
    ServerConfig mConfig;
    net::io_context mIOContext;
    beast::tcp_stream mStream;
};