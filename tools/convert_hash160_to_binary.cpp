#include "util/utils.h"
#include "util/common.h"
#include "cuda/defines.cuh"

#include <string>
#include <unordered_set>
#include <set>
#include <vector>

#include <boost/log/trivial.hpp>
#include <boost/log/utility/setup.hpp>
#include <boost/iostreams/device/mapped_file.hpp>


bool loadFileToMemoryAndValidate(const std::string_view fileName)
{
    return true;
}

int main(int argc, char* argv[])
{
    utils::Timer timer;

    boost::iostreams::mapped_file_source file;
    boost::log::add_console_log(std::cerr, boost::log::keywords::auto_flush = true);

    if (argc != 2)
    {
        BOOST_LOG_TRIVIAL(error) << "Usage: " << argv[0] << " <filename>";
        return -1;
    }

    const std::string hash160TargetsFilepath = argv[1];

    timer.start();

    file.open(hash160TargetsFilepath);
    if (!file.is_open())
    {
        BOOST_LOG_TRIVIAL(error) << "Unable to open " << hash160TargetsFilepath;
        return -2;
    }

    BOOST_LOG_TRIVIAL(info) << "Loading RipeMD-160 hashes from: " << hash160TargetsFilepath;

    const char* data = file.data();
    const size_t size = file.size();
    constexpr size_t chunkSize = 40;  // Each chunk is 20 bytes (without newlines)

    std::vector<hash160> mHash160Targets;
    mHash160Targets.reserve(size/chunkSize);

    // Read the file in fixed-size chunks of 20 bytes
    for (size_t i = 0; i < size;)
    {
        if (i + chunkSize <= size)
        {
            // Convert the 20-byte chunk into an array of uint32_t[5]
            mHash160Targets.emplace_back(utils::hexToHash160(data + i));

            // Move to the next chunk
            i += chunkSize;
        }

        // Skip any newlines or whitespace characters
        while (i < size && (data[i] == '\n' || data[i] == '\r' || data[i] == ' '))
        {
            ++i;
        }
    }

    // Close the file
    file.close();

    for (uint32_t i = mHash160Targets.size() - 10; i < mHash160Targets.size(); ++i)
    {
        BOOST_LOG_TRIVIAL(info) << utils::convertToHexString(mHash160Targets[i].h, 5);
    }

    const auto fileReadTimeS = static_cast<float>(timer.getTime()) / 1000;
    BOOST_LOG_TRIVIAL(info) << "Loaded " << utils::formatThousands(mHash160Targets.size())
                            << " hashes, (" << utils::format("%.02fs | %.02f", fileReadTimeS, static_cast<double>(sizeof(hash160) * mHash160Targets.size()) / MB) << " Mb)";

    // timer.start();
    // std::set<hash160> hash160Set(
    //         std::make_move_iterator(mHash160Targets.begin()),
    //         std::make_move_iterator(mHash160Targets.end())
    //     );
    // BOOST_LOG_TRIVIAL(info) << "vector to set took: " << utils::format("%.02fs", static_cast<float>(timer.getTime()) / 1000) << ", set size: " << hash160Set.size();


    return 0;
}