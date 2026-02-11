#include "xpart_manager.h"
#include "utils.h"
#include "config.h"
#include "http_client.h"

#include <boost/log/trivial.hpp>
#include <boost/beast/http.hpp>
#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <format>
#include <thread>
#include <vector>

namespace http = boost::beast::http;

// Одна карта ~4 ключа/мин → цель ~1 запрос get_number в минуту. Буфер 1.5 мин = 6 ключей на карту.
constexpr unsigned int kBufferMinutesXKeysPerGpu = 6;
constexpr size_t kMarkDoneMinBatchSize = 3;
constexpr size_t kMarkDoneBatchSize = 500;
constexpr uint32_t kGetNumberMaxCount = 1000;
constexpr unsigned int kFetcherSleepMsWhenFull = 200;  // когда очередь полная — реже проверять
// Refill только когда очередь опустилась ниже порога (например 30% от целевого размера)
constexpr unsigned int kRefillThresholdPercent = 50;  // refill при currentSize < targetQueueSize * 50%

struct XPartManager::Impl
{
    std::shared_ptr<HttpClient> httpClientFetcher;   // get_number only – not blocked by mark_done
    std::shared_ptr<HttpClient> httpClientMarkDone;  // mark_done only
    bool randomMode;
    std::atomic<bool> stopFlag{false};

    std::queue<uint32_t> xPartQueue;
    std::mutex queueMutex;
    std::condition_variable queueCondition;

    std::thread fetcherThread;
    std::queue<uint32_t> markDoneQueue;
    std::mutex markDoneMutex;
    std::condition_variable markDoneCondition;
    std::thread markDoneThread;

    size_t targetQueueSize;
    size_t gpuCount;
    size_t markDoneMinBatchSize;  // min queue size before sending mark_done batch, scales with GPU count

    explicit Impl(std::shared_ptr<HttpClient> clientFetcher, std::shared_ptr<HttpClient> clientMarkDone, bool random, size_t gpuCount_)
        : httpClientFetcher(std::move(clientFetcher))
        , httpClientMarkDone(std::move(clientMarkDone))
        , randomMode(random)
        , targetQueueSize(std::max<size_t>(4u, kBufferMinutesXKeysPerGpu * std::max<size_t>(gpuCount_, 1)))
        , gpuCount(std::max<size_t>(1, gpuCount_))
        , markDoneMinBatchSize(std::max(kMarkDoneMinBatchSize, gpuCount))
    {
        BOOST_LOG_TRIVIAL(info) << std::format("XPartManager: queue buffer = {} numbers, refill when < {} ({}%), {} GPU(s), mark_done min batch = {}", targetQueueSize, std::max<size_t>(1, targetQueueSize * kRefillThresholdPercent / 100), kRefillThresholdPercent, gpuCount, markDoneMinBatchSize);
        fetcherThread = std::thread([this]() { fetcherWorker(); });
        markDoneThread = std::thread([this]() { markDoneWorker(); });
    }

    ~Impl()
    {
        stop();
    }

    void stop()
    {
        if (stopFlag.exchange(true))
        {
            return; // Already stopped
        }

        // Wake up threads
        queueCondition.notify_all();
        markDoneCondition.notify_all();

        // Wait for threads to finish
        if (fetcherThread.joinable())
        {
            fetcherThread.join();
        }
        if (markDoneThread.joinable())
        {
            markDoneThread.join();
        }
    }

    void fetcherWorker()
    {
        while (!stopFlag)
        {
            size_t currentSize = 0;
            {
                std::lock_guard<std::mutex> lock(queueMutex);
                currentSize = xPartQueue.size();
            }

            const size_t refillThreshold = std::max<size_t>(1, targetQueueSize * kRefillThresholdPercent / 100);
            if (currentSize < refillThreshold)
            {
                const size_t needCount = targetQueueSize - currentSize;
                const uint32_t requestCount = static_cast<uint32_t>(std::min(needCount, static_cast<size_t>(kGetNumberMaxCount)));

                if (randomMode)
                {
                    std::lock_guard<std::mutex> lock(queueMutex);
                    for (uint32_t i = 0; i < requestCount; ++i)
                    {
                        xPartQueue.push(utils::randomUINT32_t());
                    }
                    queueCondition.notify_all();
                }
                else
                {
                    try
                    {
                        std::vector<uint32_t> numbers;
                        const http::status responseCode = httpClientFetcher->getXPartNumbers(numbers, requestCount);
                        if (responseCode == http::status::ok && !numbers.empty())
                        {
                            std::lock_guard<std::mutex> lock(queueMutex);
                            for (uint32_t n : numbers)
                            {
                                xPartQueue.push(n);
                            }
                            queueCondition.notify_all();
                        }
                        else
                        {
                            if (responseCode != http::status::ok)
                            {
                                BOOST_LOG_TRIVIAL(warning) << std::format("XPartManager fetcher: getXPartNumbers failed (code: {}), falling back to single request", static_cast<int>(responseCode));
                            }
                            uint32_t single = 0;
                            if (httpClientFetcher->getXPartNumber(single) == http::status::ok)
                            {
                                std::lock_guard<std::mutex> lock(queueMutex);
                                xPartQueue.push(single);
                                queueCondition.notify_one();
                            }
                            else
                            {
                                BOOST_LOG_TRIVIAL(warning) << "XPartManager fetcher: getXPartNumber failed, pushing random X part(s)";
                                std::lock_guard<std::mutex> lock(queueMutex);
                                for (uint32_t i = 0; i < requestCount; ++i)
                                    xPartQueue.push(utils::randomUINT32_t());
                                queueCondition.notify_all();
                            }
                        }
                    }
                    catch (const std::exception& e)
                    {
                        BOOST_LOG_TRIVIAL(warning) << std::format("XPartManager fetcher: get_number request failed ({}), pushing random X part(s)", e.what());
                        std::lock_guard<std::mutex> lock(queueMutex);
                        for (uint32_t i = 0; i < requestCount; ++i)
                            xPartQueue.push(utils::randomUINT32_t());
                        queueCondition.notify_all();
                    }
                }
            }
            else
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(kFetcherSleepMsWhenFull));
            }
        }
    }

    void markDoneWorker()
    {
        while (!stopFlag)
        {
            std::unique_lock<std::mutex> lock(markDoneMutex);
            markDoneCondition.wait(lock, [this]() {
                return markDoneQueue.size() >= markDoneMinBatchSize || stopFlag;
            });

            while (!markDoneQueue.empty())
            {
                std::vector<uint32_t> batch;
                const size_t toTake = std::min(kMarkDoneBatchSize, markDoneQueue.size());
                if (toTake >= markDoneMinBatchSize || stopFlag)
                {
                    for (size_t i = 0; i < toTake && !markDoneQueue.empty(); ++i)
                    {
                        batch.push_back(markDoneQueue.front());
                        markDoneQueue.pop();
                    }
                }
                if (batch.empty())
                {
                    break;
                }
                lock.unlock();

                // Small delay between batches so we don't open 2nd/3rd connect immediately after
                // previous close (server/listen backlog or client TIME_WAIT often then accepts 3rd connect).
                constexpr unsigned int kMarkDoneDelayBetweenBatchesMs = 400;
                std::this_thread::sleep_for(std::chrono::milliseconds(kMarkDoneDelayBetweenBatchesMs));

                // Critical: if markDone is not delivered, process exits (no silent loss of progress).
                constexpr int maxRetries = 2;
                bool success = false;
                for (int attempt = 0; attempt < maxRetries && !stopFlag; ++attempt)
                {
                    try
                    {
                        success = httpClientMarkDone->markXPartDone(batch);
                        if (success)
                        {
#ifdef KEYHUNT_DEBUG_LOGS
                            if (attempt > 0)
                            {
                                BOOST_LOG_TRIVIAL(info) << std::format("markXPartDone ({} num(s)) succeeded on retry attempt {}", batch.size(), attempt + 1);
                            }
#endif
                            break;
                        }
                    }
                    catch (const std::exception& e)
                    {
                        // Exit immediately: connection/timeout exception = delivery not sent
                        BOOST_LOG_TRIVIAL(fatal) << std::format("FATAL: markDone delivery failed ({}). Exiting.", e.what());
                        std::quick_exit(1);  // avoid destructors/CUDA teardown that can cause "cudaErrorInvalidDevice"
                    }
                    if (attempt < maxRetries - 1 && !stopFlag)
                    {
                        const int delayMs = (1 << attempt) * 1000;
                        BOOST_LOG_TRIVIAL(warning) << std::format("markXPartDone ({} num(s)) failed (attempt {}/{}), retrying in {}ms...",
                                                                  batch.size(), attempt + 1, maxRetries, delayMs);
                        std::this_thread::sleep_for(std::chrono::milliseconds(delayMs));
                    }
                }

                // Exit if after all retries server still did not accept (and we are not shutting down)
                if (!success && !stopFlag)
                {
                    BOOST_LOG_TRIVIAL(fatal) << std::format("FATAL: markDone delivery failed for {} num(s) after {} retries. Exiting.", batch.size(), maxRetries);
                    std::quick_exit(1);
                }
                if (stopFlag && !batch.empty())
                {
                    BOOST_LOG_TRIVIAL(warning) << std::format("markXPartDone ({} num(s)) cancelled due to shutdown", batch.size());
                }

                lock.lock();
            }
        }
    }

    // Max wait for next X part (avoids infinite hang if server/HTTP is stuck and log just stops)
    static constexpr unsigned int kGetNextXPartTimeoutSec = 90;
    static constexpr unsigned int kWaitChunkSec = 30;  // log every Ns so user sees process is alive

    uint32_t getNextXPart()
    {
        std::unique_lock<std::mutex> lock(queueMutex);

        unsigned int waitedSec = 0;
        while (waitedSec < kGetNextXPartTimeoutSec)
        {
            const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(kWaitChunkSec);
            const bool hasItem = queueCondition.wait_until(lock, deadline, [this]() {
                return !xPartQueue.empty() || stopFlag;
            });
            if (hasItem && !xPartQueue.empty())
                break;
            if (stopFlag && xPartQueue.empty())
                break;
            waitedSec += kWaitChunkSec;
            if (waitedSec < kGetNextXPartTimeoutSec && xPartQueue.empty())
                BOOST_LOG_TRIVIAL(info) << std::format("XPartManager: waiting for X part... ({}s/{}s)", waitedSec, kGetNextXPartTimeoutSec);
        }

        const bool timedOut = (waitedSec >= kGetNextXPartTimeoutSec && xPartQueue.empty());
        if (timedOut)
        {
            BOOST_LOG_TRIVIAL(warning) << std::format("XPartManager: no X part within {}s (queue empty – check XPartManager fetcher / Http client logs above for connect or timeout errors), using random X part", kGetNextXPartTimeoutSec);
            return utils::randomUINT32_t();
        }

        if (stopFlag && xPartQueue.empty())
        {
            lock.unlock();
            BOOST_LOG_TRIVIAL(warning) << "XPartManager stopped, falling back to random X part";
            return utils::randomUINT32_t();
        }

        if (xPartQueue.empty())
        {
            lock.unlock();
            BOOST_LOG_TRIVIAL(warning) << "XPartManager queue unexpectedly empty, falling back to random";
            return utils::randomUINT32_t();
        }

        uint32_t xPart = xPartQueue.front();
        xPartQueue.pop();
        return xPart;
    }

    void markXPartDoneAsync(uint32_t xPart)
    {
        std::lock_guard<std::mutex> lock(markDoneMutex);
        markDoneQueue.push(xPart);
        markDoneCondition.notify_one();
    }
};

XPartManager::XPartManager(std::shared_ptr<HttpClient> httpClientFetcher, std::shared_ptr<HttpClient> httpClientMarkDone, bool randomMode, size_t gpuCount)
    : mImpl(std::make_unique<Impl>(std::move(httpClientFetcher), std::move(httpClientMarkDone), randomMode, gpuCount))
{
}

XPartManager::~XPartManager() = default;

uint32_t XPartManager::getNextXPart()
{
    return mImpl->getNextXPart();
}

void XPartManager::markXPartDoneAsync(uint32_t xPart)
{
    mImpl->markXPartDoneAsync(xPart);
}

void XPartManager::stop()
{
    mImpl->stop();
}
