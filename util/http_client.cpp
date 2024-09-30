#include "http_client.h"
#include "utils.h"
#include "config.h"

#include <nlohmann/json.hpp>

#include <boost/log/trivial.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/version.hpp>

#include <boost/asio/io_context.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/core/tcp_stream.hpp>
#include <boost/beast/core/flat_buffer.hpp>

using tcp = net::ip::tcp;

struct HttpClient::Impl
{
    ServerConfig config;
    net::io_context ioc;
    beast::tcp_stream tcpStream;

    explicit Impl(const ServerConfig& config) : config(config), ioc(), tcpStream(ioc)
    {
        if (!utils::validateUrl(config.url))
        {
            BOOST_LOG_TRIVIAL(error) << "Error: Invalid URL or host.";
            return;
        }

        if (!utils::validateUUID(config.authorisationHeader))
        {
            BOOST_LOG_TRIVIAL(error) << "Error: Invalid Authorization token.";
            return;
        }
    }

    http::status get(const std::string& target, http::response<http::dynamic_body>& response)
    {
        constexpr uint32_t httpVersion{11}; // HTTP1.1 version

        http::status responseCode{http::status::not_found};
        try
        {
            // Resolve the host
            tcp::resolver resolver(ioc);
            auto const results = resolver.resolve(config.url, config.port);

            // Connect to the server
            tcpStream.connect(results);

            // Set up the HTTP GET request with the Authorization header
            http::request<http::string_body> request{http::verb::get, target, httpVersion};
            request.set(http::field::host, config.url);
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

    http::status getNumber(uint32_t& number)
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
        }

        if (json.contains("number") && json["number"].is_number())
        {
            number = json["number"];
        }

        return responseCode;
    }
};


HttpClient::HttpClient(const ServerConfig& config) : mImpl(std::make_unique<Impl>(config)) {}
HttpClient::~HttpClient() = default;

http::status HttpClient::getNumber(uint32_t& number)
{
    return mImpl->getNumber(number);
}
