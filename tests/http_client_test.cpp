#define CATCH_CONFIG_MAIN
#include <catch2/catch_all.hpp>

#include "util/http_client.h"
#include "util/config.h"

static ServerConfig config{
    .host = "91.200.150.93",
    .port = "3600"
};
std::unique_ptr<HttpClient> clientPtr;
static void globalSetup()
{
    HttpClient client(config);
    http::status status = client.generateToken(config.authorisationHeader);
    fprintf(stderr, "status: %d, authorisationHeader: %s\n", status, config.authorisationHeader.c_str());

    clientPtr = std::make_unique<HttpClient>(config);
}

// Static variable ensures that the setup is run once before any test
static bool setupDone = (globalSetup(), true);

TEST_CASE("Http client test: get_number")
{
    uint32_t number1{0};
    REQUIRE(http::status::ok == clientPtr->getNumber(number1));
    REQUIRE(number1 > 0);

    uint32_t number2{0};
    REQUIRE(http::status::ok == clientPtr->getNumber(number2));
    REQUIRE(number2 > 0);

    REQUIRE(number1 + 1 == number2);
}

TEST_CASE("Http client test mark_done")
{
    uint32_t number{2};
    REQUIRE(true == clientPtr->markDone(number));
    REQUIRE(number > 0);
}

TEST_CASE("Http client test set_found")
{
    const std::string privateKeyHex = "test";
    uint32_t number{2};
    REQUIRE(true == clientPtr->setFound(number, privateKeyHex));
}
