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
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>
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

    void connectToServer()
    {
        beast::error_code ec;
        
        // Try to parse as IP address first (more efficient for IP addresses)
        ec.clear();
        net::ip::address_v4 ipv4 = net::ip::address_v4::from_string(config.host.c_str(), ec);
        if (!ec)
        {
            // Direct connection using IP address
            try
            {
                uint16_t portNum = static_cast<uint16_t>(std::stoul(config.port));
                tcp::endpoint endpoint(ipv4, portNum);
                ec.clear();
                tcpStream.socket().connect(endpoint, ec);
                if (ec)
                {
                    throw beast::system_error{ec};
                }
            }
            catch (const std::exception& e)
            {
                BOOST_LOG_TRIVIAL(error) << "Failed to connect to IP " << config.host << ":" << config.port << " - " << e.what();
                throw;
            }
        }
        else
        {
            // Use resolver for hostname
            tcp::resolver resolver(ioc);
            auto const results = resolver.resolve(tcp::v4(), config.host, config.port);
            tcpStream.connect(results);
        }
    }

    http::status get(const std::string& target, http::response<http::dynamic_body>& response)
    {
        std::lock_guard<std::mutex> lock(connectionMutex);

        http::status responseCode{http::status::not_found};
        try
        {
            // Validate configuration
            if (config.host.empty() || config.port.empty())
            {
                BOOST_LOG_TRIVIAL(error) << "Http client failed: host or port is empty. Host: '" << config.host << "', Port: '" << config.port << "'";
                return responseCode;
            }

            // Close socket if it's already open
            beast::error_code ec;
            if (tcpStream.socket().is_open())
            {
                tcpStream.socket().shutdown(tcp::socket::shutdown_both, ec);
                tcpStream.socket().close(ec);
            }

            // Connect to the server (handles both IP addresses and hostnames)
            connectToServer();

            // Set up the HTTP GET request with the Authorization header
            http::request<http::string_body> request{http::verb::get, target, http11Version};
            request.set(http::field::host, config.host);
            request.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
            request.set(http::field::authorization, config.authorisationHeader);
            if (!config.machineId.empty())
            {
                request.set("X-Machine-Id", config.machineId);
            }

            // Send the request
            http::write(tcpStream, request);

            // Buffer is used to read raw network data
            beast::flat_buffer buffer;

            // Receive the HTTP response with error handling
            try
            {
                http::read(tcpStream, buffer, response);
                responseCode = response.result();
            }
            catch (const beast::system_error& e)
            {
                // Handle stream truncated and other network errors
                if (e.code() == beast::error::timeout || 
                    e.code() == boost::asio::error::eof ||
                    e.code() == boost::asio::error::connection_reset ||
                    e.code() == boost::asio::ssl::error::stream_truncated ||
                    e.code().category() == boost::asio::error::get_ssl_category())
                {
                    BOOST_LOG_TRIVIAL(warning) << "Http client connection error: " << e.what() << " (code: " << e.code() << ")";
                    // Try to read partial response if available
                    if (response.result() != http::status::unknown)
                    {
                        responseCode = response.result();
                    }
                    else
                    {
                        // If request was sent but response truncated, mark as timeout
                        // The caller can decide if this is acceptable (request was sent)
                        responseCode = http::status::request_timeout;
                    }
                }
                else
                {
                    throw; // Re-throw if it's not a connection error
                }
            }

            // Gracefully close the socket
            ec.clear(); // Reuse existing ec variable
            tcpStream.socket().shutdown(tcp::socket::shutdown_both, ec);
            tcpStream.socket().close(ec);

            // Handle potential errors (ignore not_connected and already_closed)
            // Errors are silently ignored as connection was successful
        }
        catch (const beast::system_error& e)
        {
            // More detailed error logging
            BOOST_LOG_TRIVIAL(error) << "Http client GET system error: " << e.what() 
                                     << " (code: " << e.code() << ", category: " << e.code().category().name() << ")";
            
            // Check if it's an SSL/stream error
            std::string errorMsg = e.what() ? std::string(e.what()) : "";
            if (e.code().category() == boost::asio::error::get_ssl_category() ||
                e.code() == boost::asio::ssl::error::stream_truncated ||
                errorMsg.find("stream truncated") != std::string::npos)
            {
                BOOST_LOG_TRIVIAL(error) << "SSL/Stream truncated error detected. This may indicate:";
                BOOST_LOG_TRIVIAL(error) << "  - Server closed connection prematurely";
                BOOST_LOG_TRIVIAL(error) << "  - Network timeout or connection reset";
                BOOST_LOG_TRIVIAL(error) << "  - Incomplete response received";
            }
        }
        catch (const std::exception& e)
        {
            BOOST_LOG_TRIVIAL(error) << "Http client GET failed: " << e.what();
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

            // Validate configuration
            if (config.host.empty() || config.port.empty())
            {
                BOOST_LOG_TRIVIAL(error) << "Http client failed: host or port is empty. Host: '" << config.host << "', Port: '" << config.port << "'";
                return responseCode;
            }

            // Close socket if it's already open
            beast::error_code ec;
            if (tcpStream.socket().is_open())
            {
                tcpStream.socket().shutdown(tcp::socket::shutdown_both, ec);
                tcpStream.socket().close(ec);
            }

            // Connect to the server (handles both IP addresses and hostnames)
            connectToServer();

            // Set up an HTTP POST request message
            http::request<http::string_body> req{http::verb::post, target, http11Version};
            req.set(http::field::host, config.host);
            req.set(http::field::content_type, contentType);
            req.set("Authorization", config.authorisationHeader);
            if (!config.machineId.empty())
            {
                req.set("X-Machine-Id", config.machineId);
            }
            req.body() = body;
            req.prepare_payload();

            // Send the HTTP request to the remote host
            http::write(tcpStream, req);
            // At this point, request was successfully sent to server

            // This buffer is used for reading the response
            beast::flat_buffer buffer;

            // Receive the HTTP response with error handling
            try
            {
                http::read(tcpStream, buffer, response);
                responseCode = response.result();
            }
            catch (const beast::system_error& e)
            {
                // Handle stream truncated and other network errors
                // If request was sent successfully, server likely processed it
                if (e.code() == beast::error::timeout || 
                    e.code() == boost::asio::error::eof ||
                    e.code() == boost::asio::error::connection_reset ||
                    e.code() == boost::asio::ssl::error::stream_truncated ||
                    e.code().category() == boost::asio::error::get_ssl_category())
                {
                    BOOST_LOG_TRIVIAL(warning) << "Http client connection error after request sent: " << e.what() << " (code: " << e.code() << ")";
                    BOOST_LOG_TRIVIAL(warning) << "Request was sent successfully, server likely processed it despite connection error";
                    
                    // Try to read partial response if available
                    if (response.result() != http::status::unknown)
                    {
                        responseCode = response.result();
                    }
                    else
                    {
                        // Request was sent, but response truncated - mark as accepted
                        // Caller should treat this as success since request reached server
                        responseCode = http::status::accepted; // 202 Accepted - request received but response incomplete
                    }
                }
                else
                {
                    throw; // Re-throw if it's not a connection error
                }
            }

            // Gracefully close the socket
            ec.clear(); // Reuse existing ec variable
            tcpStream.socket().shutdown(tcp::socket::shutdown_both, ec);
            tcpStream.socket().close(ec);

            // Handle potential errors (ignore not_connected and already_closed)
            // Errors are silently ignored as connection was successful
        }
        catch (const beast::system_error& e)
        {
            // More detailed error logging
            BOOST_LOG_TRIVIAL(error) << "Http client POST system error: " << e.what() 
                                     << " (code: " << e.code() << ", category: " << e.code().category().name() << ")";
            
            // Check if it's an SSL/stream error
            std::string errorMsg = e.what() ? std::string(e.what()) : "";
            if (e.code().category() == boost::asio::error::get_ssl_category() ||
                e.code() == boost::asio::ssl::error::stream_truncated ||
                errorMsg.find("stream truncated") != std::string::npos)
            {
                BOOST_LOG_TRIVIAL(error) << "SSL/Stream truncated error detected. This may indicate:";
                BOOST_LOG_TRIVIAL(error) << "  - Server closed connection prematurely";
                BOOST_LOG_TRIVIAL(error) << "  - Network timeout or connection reset";
                BOOST_LOG_TRIVIAL(error) << "  - Incomplete response received";
            }
        }
        catch (const std::exception& e)
        {
            BOOST_LOG_TRIVIAL(error) << "Http client POST failed: " << e.what();
        }

        return responseCode;
    }

    http::status generateToken(std::string& token)
    {
        const std::string target{"/generate_token"};

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
        const std::string target{"/status"};

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
        const std::string target{"/get_number"};

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
        
        // If we got accepted (202) or timeout but request was sent, consider it success
        // (server may have processed it but closed connection prematurely)
        if (responseCode == http::status::accepted || responseCode == http::status::request_timeout)
        {
            BOOST_LOG_TRIVIAL(info) << std::format("markXPartDone for {} - request sent successfully, response incomplete (code: {}) - assuming success", number, static_cast<int>(responseCode));
            return true; // Assume success if request was sent
        }
        
        const std::string resultString = beast::buffers_to_string(response.body().data());
        if (http::status::ok != responseCode)
        {
            BOOST_LOG_TRIVIAL(error) << std::format("markXPartDone for {} failed: {} (response: {})", number, static_cast<int>(responseCode), resultString);
            return false;
        }

        nlohmann::json json;
        try
        {
            json = nlohmann::json::parse(resultString);
        }
        catch (const nlohmann::json::parse_error& e)
        {
            // If JSON parse fails but we got OK status, request was likely processed
            if (responseCode == http::status::ok)
            {
                BOOST_LOG_TRIVIAL(warning) << std::format("markXPartDone for {} - JSON parse failed but got OK status, assuming success: {}", number, resultString);
                return true;
            }
            BOOST_LOG_TRIVIAL(error) << std::format("markXPartDone for {} failed, JSON parse failed: {}, parse error at byte {}\nduring paring: {}", number, e.what(),  e.byte, resultString);
            return false;
        }

        if (!(json.contains("success") && json["success"].is_boolean() && json["success"]))
        {
            BOOST_LOG_TRIVIAL(error) << std::format("markXPartDone for {} failed: {}", number, resultString);
            return false;
        }

        // Logging is handled by XPartManager if used, so we don't log here to avoid duplication
        return true;
    }

    bool setXPartFound(const uint32_t number, const std::string& privateKeyHex)
    {
        const std::string body = std::format(R"({{"num": {}}})", number);

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
