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
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/connect.hpp>
#include <boost/beast/http.hpp>

#include <atomic>
#include <chrono>
#include <memory>
#include <utility>

#if defined(_WIN32) || defined(_WIN64)
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <sys/types.h>
#endif

using tcp = net::ip::tcp;
namespace ssl = net::ssl;

struct HttpClient::Impl
{
    ServerConfig config;
    net::io_context ioc;
    std::unique_ptr<beast::tcp_stream> tcpStream;  // new stream per request to avoid "second connect" hang
    std::mutex connectionMutex;

    explicit Impl(ServerConfig config) : config(std::move(config)), ioc(), tcpStream(std::make_unique<beast::tcp_stream>(ioc)) {}

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

    // Timeouts to prevent infinite hang when server is slow/unreachable (log stops without errors)
    static constexpr int kConnectTimeoutSec = 45;   // connect() can hang indefinitely; 45s for slow/far networks
    static constexpr int kReadWriteTimeoutSec = 45;

    void setSocketTimeouts(beast::tcp_stream& stream)
    {
#if defined(_WIN32) || defined(_WIN64)
        DWORD timeoutMs = static_cast<DWORD>(kReadWriteTimeoutSec) * 1000;
        const auto* opt = reinterpret_cast<const char*>(&timeoutMs);
        if (setsockopt(stream.socket().native_handle(), SOL_SOCKET, SO_RCVTIMEO, opt, sizeof(timeoutMs)) != 0 ||
            setsockopt(stream.socket().native_handle(), SOL_SOCKET, SO_SNDTIMEO, opt, sizeof(timeoutMs)) != 0)
        {
            BOOST_LOG_TRIVIAL(warning) << "Http client: failed to set socket timeout (" << kReadWriteTimeoutSec << "s), requests may hang";
        }
#else
        struct timeval tv;
        tv.tv_sec = kReadWriteTimeoutSec;
        tv.tv_usec = 0;
        if (setsockopt(stream.socket().native_handle(), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0 ||
            setsockopt(stream.socket().native_handle(), SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) != 0)
        {
            BOOST_LOG_TRIVIAL(warning) << "Http client: failed to set socket timeout (" << kReadWriteTimeoutSec << "s), requests may hang";
        }
#endif
    }

    void connectToServer(beast::tcp_stream& stream)
    {
        beast::error_code ec;
        ec.clear();
        net::ip::address_v4 ipv4 = net::ip::address_v4::from_string(config.host.c_str(), ec);
        if (!ec)
        {
            uint16_t portNum = static_cast<uint16_t>(std::stoul(config.port));
            tcp::endpoint endpoint(ipv4, portNum);
            connectWithTimeout(stream, endpoint);
        }
        else
        {
            tcp::resolver resolver(ioc);
            auto const results = resolver.resolve(tcp::v4(), config.host, config.port);
            connectWithTimeout(stream, results);
        }
        setSocketTimeouts(stream);
    }

    void connectWithTimeout(beast::tcp_stream& stream, const tcp::endpoint& endpoint)
    {
        BOOST_LOG_TRIVIAL(info) << "Http client: connecting to " << config.host << ":" << config.port << " (" << kConnectTimeoutSec << "s timeout)...";
        ioc.restart();
        beast::error_code connectEc;
        std::atomic<bool> done{false};
        bool timedOut = false;

        net::steady_timer timer(ioc);
        timer.expires_after(std::chrono::seconds(kConnectTimeoutSec));
        timer.async_wait([&](beast::error_code e) {
            if (!e) { timedOut = true; stream.socket().cancel(connectEc); }
            done = true;
        });
        stream.socket().async_connect(endpoint, [&](beast::error_code e) { connectEc = e; done = true; });

        while (!done)
            ioc.run_one();
        timer.cancel();

        const bool canceledOrTimeout = timedOut || connectEc == net::error::operation_aborted ||
            connectEc.value() == static_cast<int>(boost::system::errc::operation_canceled);
        if (canceledOrTimeout)
        {
            BOOST_LOG_TRIVIAL(warning) << "Http client: connect timeout or canceled (" << kConnectTimeoutSec << "s) to " << config.host << ":" << config.port;
            throw beast::system_error{beast::error_code{beast::error::timeout}};
        }
        if (connectEc)
        {
            BOOST_LOG_TRIVIAL(error) << "Failed to connect to " << config.host << ":" << config.port << " - " << connectEc.message();
            throw beast::system_error{connectEc};
        }
        BOOST_LOG_TRIVIAL(info) << "Http client: connected to " << config.host << ":" << config.port;
    }

    void connectWithTimeout(beast::tcp_stream& stream, const tcp::resolver::results_type& results)
    {
        BOOST_LOG_TRIVIAL(info) << "Http client: connecting to " << config.host << ":" << config.port << " (" << kConnectTimeoutSec << "s timeout)...";
        ioc.restart();
        beast::error_code connectEc;
        std::atomic<bool> done{false};
        bool timedOut = false;

        net::steady_timer timer(ioc);
        timer.expires_after(std::chrono::seconds(kConnectTimeoutSec));
        timer.async_wait([&](beast::error_code e) {
            if (!e) { timedOut = true; stream.socket().cancel(connectEc); }
            done = true;
        });
        net::async_connect(stream.socket(), results.begin(), results.end(),
            [&](beast::error_code e, tcp::resolver::results_type::iterator) { connectEc = e; done = true; });

        while (!done)
            ioc.run_one();
        timer.cancel();

        const bool canceledOrTimeout = timedOut || connectEc == net::error::operation_aborted ||
            connectEc.value() == static_cast<int>(boost::system::errc::operation_canceled);
        if (canceledOrTimeout)
        {
            BOOST_LOG_TRIVIAL(warning) << "Http client: connect timeout or canceled (" << kConnectTimeoutSec << "s) to " << config.host << ":" << config.port;
            throw beast::system_error{beast::error_code{beast::error::timeout}};
        }
        if (connectEc)
        {
            BOOST_LOG_TRIVIAL(error) << "Failed to connect to " << config.host << ":" << config.port << " - " << connectEc.message();
            throw beast::system_error{connectEc};
        }
        BOOST_LOG_TRIVIAL(info) << "Http client: connected to " << config.host << ":" << config.port;
    }

    http::status get(const std::string& target, http::response<http::dynamic_body>& response)
    {
        std::lock_guard<std::mutex> lock(connectionMutex);

        http::status responseCode{http::status::not_found};
        try
        {
            if (config.host.empty() || config.port.empty())
            {
                BOOST_LOG_TRIVIAL(error) << "Http client failed: host or port is empty. Host: '" << config.host << "', Port: '" << config.port << "'";
                return responseCode;
            }

            // New stream per request to avoid "second connect" hang when reusing same socket
            tcpStream = std::make_unique<beast::tcp_stream>(ioc);
            connectToServer(*tcpStream);

            http::request<http::string_body> request{http::verb::get, target, http11Version};
            request.set(http::field::host, config.host);
            request.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
            request.set(http::field::authorization, config.authorisationHeader);
            if (!config.machineId.empty())
            {
                request.set("X-Machine-Id", config.machineId);
            }

            http::write(*tcpStream, request);

            beast::flat_buffer buffer;

            try
            {
                http::read(*tcpStream, buffer, response);
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

            beast::error_code ec;
            tcpStream->socket().shutdown(tcp::socket::shutdown_both, ec);
            tcpStream->socket().close(ec);
        }
        catch (const beast::system_error& e)
        {
            BOOST_LOG_TRIVIAL(error) << "Http client GET system error: " << e.what()
                                     << " (code: " << e.code() << ", category: " << e.code().category().name() << ")";
            if (e.code().category() == boost::asio::error::get_ssl_category() ||
                e.code() == boost::asio::ssl::error::stream_truncated ||
                (e.what() && std::string(e.what()).find("stream truncated") != std::string::npos))
            {
                BOOST_LOG_TRIVIAL(error) << "SSL/Stream truncated – server closed or network timeout";
            }
            throw;  // rethrow so caller (e.g. XPartManager fetcher) can log and handle
        }
        catch (const std::exception& e)
        {
            BOOST_LOG_TRIVIAL(error) << "Http client GET failed: " << e.what();
            throw;
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

            tcpStream = std::make_unique<beast::tcp_stream>(ioc);
            connectToServer(*tcpStream);

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

            http::write(*tcpStream, req);

            beast::flat_buffer buffer;

            try
            {
                http::read(*tcpStream, buffer, response);
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

            beast::error_code ec;
            tcpStream->socket().shutdown(tcp::socket::shutdown_both, ec);
            tcpStream->socket().close(ec);
        }
        catch (const beast::system_error& e)
        {
            BOOST_LOG_TRIVIAL(error) << "Http client POST system error: " << e.what()
                                     << " (code: " << e.code() << ", category: " << e.code().category().name() << ")";
            if (e.code().category() == boost::asio::error::get_ssl_category() ||
                e.code() == boost::asio::ssl::error::stream_truncated ||
                (e.what() && std::string(e.what()).find("stream truncated") != std::string::npos))
            {
                BOOST_LOG_TRIVIAL(error) << "SSL/Stream truncated – server closed or network timeout";
            }
            throw;  // rethrow so caller (e.g. markDoneWorker) can handle
        }
        catch (const std::exception& e)
        {
            BOOST_LOG_TRIVIAL(error) << "Http client POST failed: " << e.what();
            throw;
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
        http::response<http::dynamic_body> response;
        try
        {
            if (http::status::ok != get(target, response))
                return false;
            return true;
        }
        catch (const std::exception&)
        {
            return false;  // connection error / timeout – server considered not alive
        }
    }

    http::status getXPartNumber(uint32_t& number)
    {
        std::vector<uint32_t> numbers;
        const http::status code = getXPartNumbers(numbers, 1);
        if (code == http::status::ok && !numbers.empty())
        {
            number = numbers.front();
        }
        return code;
    }

    http::status getXPartNumbers(std::vector<uint32_t>& numbers, uint32_t count = 1)
    {
        const uint32_t reqCount = (count >= 1 && count <= 1000) ? count : 1;
        const std::string target = std::format("/get_number?count={}", reqCount);

        http::response<http::dynamic_body> response;
        const http::status responseCode = get(target, response);
        if (http::status::ok != responseCode)
        {
            return responseCode;
        }

        std::string bodyString = beast::buffers_to_string(response.body().data());
        nlohmann::json json;
        try
        {
            json = nlohmann::json::parse(bodyString);
        }
        catch (const nlohmann::json::parse_error& e)
        {
            BOOST_LOG_TRIVIAL(error) << std::format("JSON parse failed: {}, parse error at byte {}\nduring paring: {}", e.what(), e.byte, bodyString);
            return http::status::not_found;
        }

        numbers.clear();
        if (json.contains("numbers") && json["numbers"].is_array())
        {
            for (const auto& v : json["numbers"])
            {
                if (v.is_number_unsigned())
                {
                    numbers.push_back(v.get<uint32_t>());
                }
            }
        }

        return responseCode;
    }

    bool markXPartDone(uint32_t number)
    {
        return markXPartDone(std::vector<uint32_t>{number});
    }

    bool markXPartDone(const std::vector<uint32_t>& numbers)
    {
        if (numbers.empty())
        {
            return true;
        }

        std::string body;
        if (numbers.size() == 1)
        {
            body = std::format(R"({{"num": {}}})", numbers.front());
        }
        else
        {
            body = R"({"nums": [)";
            for (size_t i = 0; i < numbers.size(); ++i)
            {
                if (i > 0)
                {
                    body += ',';
                }
                body += std::to_string(numbers[i]);
            }
            body += "]}";
        }

        http::response<http::dynamic_body> response;
        http::status responseCode = postJson("/mark_done", body, response);

        if (responseCode == http::status::accepted || responseCode == http::status::request_timeout)
        {
#ifdef KEYHUNT_DEBUG_LOGS
            BOOST_LOG_TRIVIAL(info) << std::format("markXPartDone ({} num(s)) - request sent, response incomplete (code: {}) - assuming success", numbers.size(), static_cast<int>(responseCode));
#endif
            return true;
        }

        const std::string resultString = beast::buffers_to_string(response.body().data());
        if (http::status::ok != responseCode)
        {
            const std::string responsePreview = resultString.empty() ? "(no response body – connection error or timeout?)" : resultString;
            BOOST_LOG_TRIVIAL(error) << std::format("markXPartDone failed: {} (response: {})", static_cast<int>(responseCode), responsePreview);
            return false;
        }

        nlohmann::json json;
        try
        {
            json = nlohmann::json::parse(resultString);
        }
        catch (const nlohmann::json::parse_error& e)
        {
            if (responseCode == http::status::ok)
            {
#ifdef KEYHUNT_DEBUG_LOGS
                BOOST_LOG_TRIVIAL(warning) << std::format("markXPartDone - JSON parse failed but OK status, assuming success: {}", resultString);
#endif
                return true;
            }
            BOOST_LOG_TRIVIAL(error) << std::format("markXPartDone failed, JSON parse: {}", e.what());
            return false;
        }

        if (!(json.contains("success") && json["success"].is_boolean() && json["success"]))
        {
            BOOST_LOG_TRIVIAL(error) << std::format("markXPartDone failed: {}", resultString);
            return false;
        }

        return true;
    }

    bool setXPartFound(uint32_t x, uint32_t y)
    {
        const std::string body = std::format(R"({{"x": {}, "y": {}}})", x, y);

        http::response<http::dynamic_body> response;
        const http::status responseCode = postJson("/set_found", body, response);
        const std::string resultString = beast::buffers_to_string(response.body().data());
        if (http::status::ok != responseCode)
        {
            BOOST_LOG_TRIVIAL(error) << std::format("setXPartFound failed: {}", resultString);
            BOOST_LOG_TRIVIAL(fatal) << "setXPartFound PANIC: backend rejected";
            return false;
        }

        nlohmann::json json;
        try
        {
            json = nlohmann::json::parse(resultString);
        }
        catch (const nlohmann::json::parse_error& e)
        {
            BOOST_LOG_TRIVIAL(error) << std::format("setXPartFound failed, JSON parse failed: {}, parse error at byte {}\nduring parsing: {}", e.what(), e.byte, resultString);
            BOOST_LOG_TRIVIAL(fatal) << "setXPartFound PANIC: invalid response";
            return false;
        }

        if (!(json.contains("success") && json["success"].is_boolean() && json["success"]))
        {
            BOOST_LOG_TRIVIAL(error) << std::format("setXPartFound failed: {}", resultString);
            BOOST_LOG_TRIVIAL(fatal) << "setXPartFound PANIC: success=false";
            return false;
        }

#ifdef KEYHUNT_DEBUG_LOGS
        BOOST_LOG_TRIVIAL(trace) << "setXPartFound done";
#endif
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

http::status HttpClient::getXPartNumbers(std::vector<uint32_t>& numbers, uint32_t count) const
{
    return mImpl->getXPartNumbers(numbers, count);
}

bool HttpClient::markXPartDone(const uint32_t number) const
{
    return mImpl->markXPartDone(number);
}

bool HttpClient::markXPartDone(const std::vector<uint32_t>& numbers) const
{
    return mImpl->markXPartDone(numbers);
}

bool HttpClient::setXPartFound(uint32_t x, uint32_t y) const
{
    return mImpl->setXPartFound(x, y);
}
