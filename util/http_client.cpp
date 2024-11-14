#include "http_client.h"
#include "utils.h"
#include "config.h"

#include <nlohmann/json.hpp>

#include <boost/log/trivial.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/version.hpp>
#include <boost/beast/core/tcp_stream.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/beast/http.hpp>

#include <utility>

using tcp = net::ip::tcp;
namespace ssl = net::ssl;

struct HttpClient::Impl
{
    ServerConfig config;
    net::io_context ioc;
    beast::tcp_stream tcpStream;
    std::mutex connectionMutex;

    explicit Impl(ServerConfig config) : config(std::move(config)), ioc(), tcpStream(ioc) {}

    Impl(const Impl& other) = delete;
    Impl(const Impl&& other) = delete;
    Impl& operator=(const Impl& other) = delete;
    Impl& operator=(const Impl&& other) = delete;

    [[nodiscard]] std::string hostConfig() const
    {
        std::string maskedToken;
        if (config.authorisationHeader.size() > 4)
        {
            maskedToken = std::format("{:*>{}}", config.authorisationHeader.substr(config.authorisationHeader.size() - 4), config.authorisationHeader.size());
        }
        return std::format("{}:{} | {}", config.host, config.port, maskedToken);
    }

    http::status get(const std::string& target, http::response<http::dynamic_body>& response)
    {
        std::lock_guard<std::mutex> lock(connectionMutex);

        http::status responseCode{http::status::not_found};
        try
        {
            // Resolve the host
            tcp::resolver resolver(ioc);

            // Connect to the server
            auto const results = resolver.resolve(config.host, config.port);
            tcpStream.connect(results);

            // Set up the HTTP GET request with the Authorization header
            http::request<http::string_body> request{http::verb::get, target, http11Version};
            request.set(http::field::host, config.host);
            request.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
            request.set(http::field::authorization, config.authorisationHeader);

            // Send the request
            http::write(tcpStream, request);

            // Buffer is used to read raw network data
            beast::flat_buffer buffer;

            // Receive the HTTP response
            http::read(tcpStream, buffer, response);

            responseCode = response.result();

            // Gracefully close the socket
            beast::error_code ec;
            tcpStream.socket().shutdown(tcp::socket::shutdown_both, ec);

            // Handle potential errors
            if (ec && ec != beast::errc::not_connected)
            {
                throw beast::system_error{ec};
            }
        }
        catch (const std::exception& e)
        {
            BOOST_LOG_TRIVIAL(error) << "Http client failed: " << e.what();
        }

        return responseCode;
    }

    // Core function to make a POST request
    http::status postJson(const std::string& target, const std::string& body, http::response<http::dynamic_body>& response)
    {
        std::lock_guard<std::mutex> lock(connectionMutex);

        http::status responseCode{http::status::not_found};
        try
        {
            const std::string& contentType = "application/json";

            // Resolver to translate the host name into an IP address
            tcp::resolver resolver(ioc);

            // Connect to the server
            auto const results = resolver.resolve(config.host, config.port);
            tcpStream.connect(results);

            // Set up an HTTP POST request message
            http::request<http::string_body> req{http::verb::post, target, http11Version};
            req.set(http::field::host, config.host);
            req.set(http::field::content_type, contentType);
            req.set("Authorization", config.authorisationHeader);
            req.body() = body;
            req.prepare_payload();

            // Send the HTTP request to the remote host
            http::write(tcpStream, req);

            // This buffer is used for reading the response
            beast::flat_buffer buffer;

            // Receive the HTTP response
            http::read(tcpStream, buffer, response);

            responseCode = response.result();

            // Gracefully close the socket
            beast::error_code ec;
            tcpStream.socket().shutdown(tcp::socket::shutdown_both, ec);

            // Ignore the error if it's because the connection was already closed
            if (ec && ec != beast::errc::not_connected)
            {
                throw beast::system_error{ec};
            }
        }
        catch (const std::exception& e)
        {
            BOOST_LOG_TRIVIAL(error) << "Http client failed: " << e.what();
        }

        return responseCode;
    }

    http::status generateToken(std::string& token)
    {
        const std::string target{"generate_token"};

        // Container to hold the response
        http::response<http::dynamic_body> response;
        http::status responseCode = get(target, response);
        if (http::status::ok != responseCode)
        {
            return responseCode;
        }

        // Convert the response body into a string
        std::string bodyString = beast::buffers_to_string(response.body().data());

        nlohmann::json json;
        try
        {
            json = nlohmann::json::parse(bodyString);
        }
        catch (const nlohmann::json::parse_error& e)
        {
            BOOST_LOG_TRIVIAL(error) << std::format("JSON parse failed: {}, parse error at byte {}\nduring paring: {}", e.what(),  e.byte, bodyString);
            return http::status::not_found;
        }

        if (json.contains("token") && json["token"].is_string())
        {
            token = json["token"];
        }

        return responseCode;
    }

    bool hostAlive()
    {
        const std::string target{"status"};

        // Container to hold the response
        http::response<http::dynamic_body> response;
        if (http::status::ok != get(target, response))
        {
            return false;
        }

        return true;
    }

    http::status getXPartNumber(uint32_t& number)
    {
        const std::string target{"get_number"};

        // Container to hold the response
        http::response<http::dynamic_body> response;
        http::status responseCode = get(target, response);
        if (http::status::ok != responseCode)
        {
            return responseCode;
        }

        // Convert the response body into a string
        std::string bodyString = beast::buffers_to_string(response.body().data());

        nlohmann::json json;
        try
        {
            json = nlohmann::json::parse(bodyString);
        }
        catch (const nlohmann::json::parse_error& e)
        {
            BOOST_LOG_TRIVIAL(error) << std::format("JSON parse failed: {}, parse error at byte {}\nduring paring: {}", e.what(),  e.byte, bodyString);
            return http::status::not_found;
        }

        if (json.contains("number") && json["number"].is_number())
        {
            number = json["number"];
        }

        return responseCode;
    }

    bool markXPartDone(uint32_t number)
    {
        const std::string body = std::format(R"({{"num": {}}})", number);

        http::response<http::dynamic_body> response;
        http::status responseCode = postJson("/mark_done", body, response);
        const std::string resultString = beast::buffers_to_string(response.body().data());
        if (http::status::ok != responseCode)
        {
            BOOST_LOG_TRIVIAL(error) << std::format("markXPartDone for {} failed: {}", number, resultString);
            return false;
        }

        nlohmann::json json;
        try
        {
            json = nlohmann::json::parse(resultString);
        }
        catch (const nlohmann::json::parse_error& e)
        {
            BOOST_LOG_TRIVIAL(error) << std::format("markXPartDone for {} failed, JSON parse failed: {}, parse error at byte {}\nduring paring: {}", number, e.what(),  e.byte, resultString);
            return false;
        }

        if (!(json.contains("success") && json["success"].is_boolean() && json["success"]))
        {
            BOOST_LOG_TRIVIAL(error) << std::format("markXPartDone for {} failed: {}", number, resultString);
            return false;
        }

        BOOST_LOG_TRIVIAL(trace) << std::format("markXPartDone for {}", number);
        return true;
    }

    bool setXPartFound(const uint32_t number, const std::string& privateKeyHex)
    {
        const std::string body = std::format(R"({{"num": {}, "pvk": "{}"}})", number, privateKeyHex);

        http::response<http::dynamic_body> response;
        const http::status responseCode = postJson("/set_found", body, response);
        const std::string resultString = beast::buffers_to_string(response.body().data());
        if (http::status::ok != responseCode)
        {
            BOOST_LOG_TRIVIAL(error) << std::format("setXPartFound for {} failed: {}", number, resultString);
            return false;
        }

        nlohmann::json json;
        try
        {
            json = nlohmann::json::parse(resultString);
        }
        catch (const nlohmann::json::parse_error& e)
        {
            BOOST_LOG_TRIVIAL(error) << std::format("setXPartFound for {} failed, JSON parse failed: {}, parse error at byte {}\nduring paring: {}", number, e.what(),  e.byte, resultString);
            return false;
        }

        if (!(json.contains("success") && json["success"].is_boolean() && json["success"]))
        {
            BOOST_LOG_TRIVIAL(error) << std::format("setXPartFound for {} failed: {}", number, resultString);
            return false;
        }

        BOOST_LOG_TRIVIAL(trace) << std::format("setXPartFound for {} done", number);
        return true;
    }
};

HttpClient::HttpClient(const ServerConfig& config) : mImpl(std::make_unique<Impl>(config)) {}
HttpClient::~HttpClient() = default;

std::string HttpClient::hostConfig() const
{
    return mImpl->hostConfig();
}

http::status HttpClient::generateToken(std::string& token) const
{
    return mImpl->generateToken(token);
}

bool HttpClient::hostAlive() const
{
    return mImpl->hostAlive();
}

http::status HttpClient::getXPartNumber(uint32_t& number) const
{
    return mImpl->getXPartNumber(number);
}

bool HttpClient::markXPartDone(const uint32_t number) const
{
    return mImpl->markXPartDone(number);
}

bool HttpClient::setXPartFound(const uint32_t number, const std::string& privateKeyHex) const
{
    return mImpl->setXPartFound(number, privateKeyHex);
}
