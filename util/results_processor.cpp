#include "results_processor.h"
#include "crypto_util.h"
#include "utils.h"

#include <thread>
#include <format>

#include <boost/log/trivial.hpp>

struct ResultsProcessor::Impl
{
    std::shared_ptr<GlobalContext> gContext;

    std::atomic<bool> stopFlag{false};

    std::thread thread;

    crypto::AES aesEnc;

    explicit Impl(const std::shared_ptr<GlobalContext>& context) : gContext(context), aesEnc(Config::aesKey, Config::aesIV)
    {}

    ~Impl()
    {
        stop();
    }

    Impl(const Impl& other) = delete;
    Impl& operator=(const Impl& other) = delete;

    void startHash160ResultsQueueProcessing()
    {
        thread = std::thread([this]()
        {
            BOOST_LOG_TRIVIAL(trace) << "ResultsProcessor Thread running: " << std::this_thread::get_id();

            while (!stopFlag)
            {
                Hash160SearchResult result;

                while (!gContext->hash160SearchResultsQueue->pop(result))
                {
                    if (stopFlag)
                    {
                        return;
                    }

                    std::this_thread::yield(); // If the queue is empty, yield to avoid busy-wait
                }

                /// TODO(ksh): commented as it is not needed, only useful for debugging purposes
                //const std::string publicXStr{utils::toHex(result.publicXKey, 8)};
                const std::string privateStr{utils::toHex(result.privateKey, 8)};
                const std::string hash160Str{utils::toHex(result.digest, 5)};

                const std::string resultsStr = std::format("[{}][({:>10}, {:>10}) | {:<12}] private: {}, hash160: {}",
                                                           result.cudaDeviceId, result.privateXPart, result.privateYPart, (result.compressed ? "compressed" : "uncompressed"),
                                                           privateStr, hash160Str);

                BOOST_LOG_TRIVIAL(fatal) << std::format("[{}] Found match for private key: {}", result.cudaDeviceId, result.privateXPart);

                bool online{false};

                // if it is not test: set_found for privateXPart
                if (!gContext->config.devMode())
                {
                    online |= gContext->httpClient->setXPartFound(result.privateXPart, privateStr);
                    utils::backupToTGAsync(resultsStr);
                }

                if (/*!online &&*/ !utils::writeEncResultsToFile(aesEnc, "results.enc", resultsStr))
                {
                    utils::appendToFileOnNewLine("results.txt", resultsStr);
                }
            }

            BOOST_LOG_TRIVIAL(info) << "ResultsProcessor: done";
        });
    }

    void stop()
    {
        utils::Timer t;
        BOOST_LOG_TRIVIAL(trace) << "ResultsProcessor stopping";

        stopFlag = true;
        if (thread.joinable())
        {
            thread.join();
        }

        BOOST_LOG_TRIVIAL(trace) << std::format("ResultsProcessor stopped: {} ms", t.elapsedMs());
    }
};

ResultsProcessor::ResultsProcessor(const std::shared_ptr<GlobalContext>& context) : mImpl(std::make_unique<Impl>(context)) {}
ResultsProcessor::~ResultsProcessor() = default;

void ResultsProcessor::startHash160ResultsQueueProcessing() const
{
    mImpl->startHash160ResultsQueueProcessing();
}

void ResultsProcessor::stop() const
{
    mImpl->stop();
}
