#include <util/utils.h>
#include <util/config.h>

#include <boost/log/trivial.hpp>
#include <boost/iostreams/device/mapped_file.hpp>

int main(int argc, char* argv[])
{
    utils::initOpenssl();
    utils::initLogging({LogConfig::LogType::console, "", 0});
    boost::iostreams::mapped_file_source file;

    if (argc != 2)
    {
        BOOST_LOG_TRIVIAL(error) << "Usage: " << argv[0] << " <filename>";
        return -1;
    }

    const std::string resultsFilePath = argv[1];

    const crypto::AES aesEnc(Config::aesKey, Config::aesIV);

    std::vector<std::string> results;
    if (!utils::readEncResults(aesEnc, resultsFilePath, results))
    {
        BOOST_LOG_TRIVIAL(info) << "Decrypting & Reading encrypted results fails!";
    }

    for (const auto& result : results)
    {
        BOOST_LOG_TRIVIAL(info) << result;
    }

    utils::releaseOpenssl();
    return 0;
}
