#include "util/utils.h"
#include "cuda/defines.cuh"
#include "util/config.h"

#include <string>
#include <boost/log/trivial.hpp>
#include <boost/log/utility/setup.hpp>
#include <boost/iostreams/device/mapped_file.hpp>

int main(int argc, char* argv[])
{
    utils::initLogging({LogConfig::LogType::console, "", 0});
    boost::iostreams::mapped_file_source file;

    if (argc != 2)
    {
        BOOST_LOG_TRIVIAL(error) << "Usage: " << argv[0] << " <filename>";
        return -1;
    }

    const std::string hash160TargetsFilepath = argv[1];
    Hash160Set hash160Set;

    if (!utils::readHash160HexStrFileToSet(hash160TargetsFilepath, hash160Set))
    {
        return -1;
    }

    const std::string hash160TargetsBinFilepath{hash160TargetsFilepath + ".bin"};
    if (!utils::writeHash160SetToBinaryFile(hash160TargetsBinFilepath, hash160Set))
    {
        return -1;
    }

    Hash160Set hash160SetFromBin;
    if (!utils::readSetFromHash160BinaryFile(hash160TargetsBinFilepath, hash160SetFromBin))
    {
        return -1;
    }

    BOOST_LOG_TRIVIAL(error) << "Verifying binary file is correct...";
    if (hash160Set != hash160SetFromBin)
    {
        BOOST_LOG_TRIVIAL(error) << "Written binary is not match the written memory";
    }

    BOOST_LOG_TRIVIAL(error) << "Binary file is ok!";
    return 0;
}
