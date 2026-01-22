#include "xpart_manager.h"
#include "utils.h"
#include "config.h"
#include "http_client.h"

#include <boost/log/trivial.hpp>
#include <boost/beast/http.hpp>
#include <format>
#include <chrono>
#include <thread>

namespace http = boost::beast::http;

struct XPartManager::Impl
{
    std::shared_ptr<HttpClient> httpClient;
    bool randomMode;
    std::atomic<bool> stopFlag{false};

    // Queue for pre-fetched X parts
    std::queue<uint32_t> xPartQueue;
    std::mutex queueMutex;
    std::condition_variable queueCondition;

    // Background thread for fetching X parts
    std::thread fetcherThread;

    // Background thread for marking X parts as done
    std::queue<uint32_t> markDoneQueue;
    std::mutex markDoneMutex;
    std::condition_variable markDoneCondition;
    std::thread markDoneThread;

    // Target queue size for pre-fetching (based on GPU count)
    size_t targetQueueSize;

    explicit Impl(std::shared_ptr<HttpClient> client, bool random, size_t gpuCount)
        : httpClient(std::move(client))
        , randomMode(random)
        , targetQueueSize(std::max<size_t>(gpuCount, 1)) // At least 1, ideally equal to GPU count
    {
        // Start fetcher thread
        fetcherThread = std::thread([this]() {
            fetcherWorker();
        });

        // Start mark done thread
        markDoneThread = std::thread([this]() {
            markDoneWorker();
        });
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
            // Keep queue filled
            size_t currentSize = 0;
            {
                std::lock_guard<std::mutex> lock(queueMutex);
                currentSize = xPartQueue.size();
            }

            if (currentSize < targetQueueSize)
            {
                uint32_t xPart = 0;
                bool success = false;

                if (randomMode)
                {
                    xPart = utils::randomUINT32_t();
                    success = true;
                }
                else
                {
                    http::status responseCode = httpClient->getXPartNumber(xPart);
                    success = (responseCode == http::status::ok);
                    if (!success)
                    {
                        // Log warning but still use random as fallback to keep system running
                        BOOST_LOG_TRIVIAL(warning) << std::format("getXPartNumber failed (code: {}), falling back to random X part", static_cast<int>(responseCode));
                        xPart = utils::randomUINT32_t();
                        success = true;
                    }
                }

                if (success)
                {
                    std::lock_guard<std::mutex> lock(queueMutex);
                    xPartQueue.push(xPart);
                    queueCondition.notify_one();
                }
                else
                {
                    // If we can't get X part, wait a bit before retrying
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                }
            }
            else
            {
                // Queue is full, wait a bit
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
        }
    }

    void markDoneWorker()
    {
        while (!stopFlag)
        {
            std::unique_lock<std::mutex> lock(markDoneMutex);
            markDoneCondition.wait(lock, [this]() {
                return !markDoneQueue.empty() || stopFlag;
            });

            // Process all remaining items even if stopFlag is set (graceful shutdown)
            while (!markDoneQueue.empty())
            {
                uint32_t xPart = markDoneQueue.front();
                markDoneQueue.pop();
                lock.unlock();

                // Make HTTP request with retry mechanism (blocking, but in separate thread)
                constexpr int maxRetries = 3;
                bool success = false;
                for (int attempt = 0; attempt < maxRetries && !stopFlag; ++attempt)
                {
                    success = httpClient->markXPartDone(xPart);
                    if (success)
                    {
                        if (attempt > 0)
                        {
                            BOOST_LOG_TRIVIAL(info) << std::format("markXPartDone for {} succeeded on retry attempt {}", xPart, attempt + 1);
                        }
                        break;
                    }
                    
                    // Wait before retry (exponential backoff: 1s, 2s, 4s)
                    if (attempt < maxRetries - 1 && !stopFlag)
                    {
                        const int delayMs = (1 << attempt) * 1000;
                        BOOST_LOG_TRIVIAL(warning) << std::format("markXPartDone for {} failed (attempt {}/{}), retrying in {}ms...", 
                                                                  xPart, attempt + 1, maxRetries, delayMs);
                        std::this_thread::sleep_for(std::chrono::milliseconds(delayMs));
                    }
                }
                
                if (!success && !stopFlag)
                {
                    BOOST_LOG_TRIVIAL(warning) << std::format("markXPartDone for {} failed after {} retries (non-critical, continuing)", xPart, maxRetries);
                }
                else if (success)
                {
                    BOOST_LOG_TRIVIAL(trace) << std::format("markXPartDone for {} completed", xPart);
                }
                else if (stopFlag)
                {
                    BOOST_LOG_TRIVIAL(warning) << std::format("markXPartDone for {} cancelled due to shutdown", xPart);
                }

                lock.lock();
            }
        }
    }

    uint32_t getNextXPart()
    {
        std::unique_lock<std::mutex> lock(queueMutex);
        
        // Wait for X part to be available
        queueCondition.wait(lock, [this]() {
            return !xPartQueue.empty() || stopFlag;
        });

        if (stopFlag && xPartQueue.empty())
        {
            lock.unlock();
            // If stopped and queue is empty, fallback to random
            // This should only happen during shutdown
            BOOST_LOG_TRIVIAL(warning) << "XPartManager stopped, falling back to random X part";
            return utils::randomUINT32_t();
        }

        if (xPartQueue.empty())
        {
            // This shouldn't happen, but handle gracefully
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

XPartManager::XPartManager(std::shared_ptr<HttpClient> httpClient, bool randomMode, size_t gpuCount)
    : mImpl(std::make_unique<Impl>(std::move(httpClient), randomMode, gpuCount))
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
