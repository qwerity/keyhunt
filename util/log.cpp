#include "log.h"

#include <boost/log/utility/setup.hpp>

void initLogging(const std::string& logFile)
{
    // Setting up a simple console logger
    boost::log::add_console_log(std::cerr);
    // boost::log::add_console_log(std::cerr, boost::log::keywords::format = "[%TimeStamp%] [%ThreadID%]: %Message%");

    // // Setting up a file logger
    // boost::log::add_file_log(logFile);
    // boost::log::add_file_log(logFile, boost::log::keywords::format = "[%TimeStamp%] [%ThreadID%]: %Message%");
    //
    // // Enable logging for all levels
    // boost::log::core::get()->set_filter(boost::log::trivial::severity >= boost::log::trivial::trace);

    // Add attributes like timestamp and thread id
    boost::log::add_common_attributes();
}
