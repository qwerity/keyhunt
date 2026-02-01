#include "xpart_manager.h"
#include "utils.h"
#include "config.h"
#include "http_client.h"

#include <boost/log/trivial.hpp>
#include <boost/beast/http.hpp>
#include <algorithm>
#include <format>
#include <chrono>
#include <thread>
#include <vector>

namespace http = boost::beast::http;

// Одна карта ~4 ключа/мин → цель ~1 запрос get_number в минуту к backend.
// Буфер = сколько минут работы держим в очереди, чтобы keyhunt не ждал (1.5 мин = 6 ключей на карту).
constexpr unsigned int kKeysPerMinutePerGpu = 4;
constexpr unsigned int kBufferMinutesXKeysPerGpu = 6;  // 1.5 min * 4 keys/min
constexpr size_t kMarkDoneMinBatchSize = 3; 
constexpr size_t kMarkDoneBatchSize = 500;
constexpr uint32_t kGetNumberMaxCount = 1000;
constexpr unsigned int kFetcherSleepMsWhenFull = 200;  // когда очередь полная — реже проверять

struct XPartManager::Impl
{
    std::shared_ptr<HttpClient> httpClient;
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

    // Целевой размер очереди: от числа видеокарт, заранее заполняем (~1 запрос get_number в минуту)
    size_t targetQueueSize;

    explicit Impl(std::shared_ptr<HttpClient> client, bool random, size_t gpuCount)
        : httpClient(std::move(client))
        , randomMode(random)
        , targetQueueSize(std::max<size_t>(4u, kBufferMinutesXKeysPerGpu * std::max<size_t>(gpuCount, 1)))
    {
        BOOST_LOG_TRIVIAL(info) << std::format("XPartManager: queue buffer = {} numbers (~1 request/min to backend, {} GPU(s))", targetQueueSize, std::max<size_t>(gpuCount, 1));
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

            if (currentSize < targetQueueSize)
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
                    std::vector<uint32_t> numbers;
                    const http::status responseCode = httpClient->getXPartNumbers(numbers, requestCount);
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
                            BOOST_LOG_TRIVIAL(warning) << std::format("getXPartNumbers failed (code: {}), falling back to single request", static_cast<int>(responseCode));
                        }
                        uint32_t single = 0;
                        if (httpClient->getXPartNumber(single) == http::status::ok)
                        {
                            std::lock_guard<std::mutex> lock(queueMutex);
                            xPartQueue.push(single);
                            queueCondition.notify_one();
                        }
                        else
                        {
                            BOOST_LOG_TRIVIAL(warning) << std::format("getXPartNumber failed, falling back to random X part");
                            std::lock_guard<std::mutex> lock(queueMutex);
                            xPartQueue.push(utils::randomUINT32_t());
                            queueCondition.notify_one();
                        }
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
            // Ждём минимум kMarkDoneMinBatchSize штук (или остановки) — mark_done кусками, не по одному
            markDoneCondition.wait(lock, [this]() {
                return markDoneQueue.size() >= kMarkDoneMinBatchSize || stopFlag;
            });

            while (!markDoneQueue.empty())
            {
                std::vector<uint32_t> batch;
                const size_t toTake = std::min(kMarkDoneBatchSize, markDoneQueue.size());
                // При остановке отправляем что есть; иначе только если набрали хотя бы kMarkDoneMinBatchSize
                if (toTake >= kMarkDoneMinBatchSize || stopFlag)
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

                constexpr int maxRetries = 3;
                bool success = false;
                for (int attempt = 0; attempt < maxRetries && !stopFlag; ++attempt)
                {
                    success = httpClient->markXPartDone(batch);
                    if (success)
                    {
                        if (attempt > 0)
                        {
                            BOOST_LOG_TRIVIAL(info) << std::format("markXPartDone ({} num(s)) succeeded on retry attempt {}", batch.size(), attempt + 1);
                        }
                        break;
                    }
                    if (attempt < maxRetries - 1 && !stopFlag)
                    {
                        const int delayMs = (1 << attempt) * 1000;
                        BOOST_LOG_TRIVIAL(warning) << std::format("markXPartDone ({} num(s)) failed (attempt {}/{}), retrying in {}ms...",
                                                                  batch.size(), attempt + 1, maxRetries, delayMs);
                        std::this_thread::sleep_for(std::chrono::milliseconds(delayMs));
                    }
                }

                if (!success && !stopFlag)
                {
                    BOOST_LOG_TRIVIAL(warning) << std::format("markXPartDone ({} num(s)) failed after {} retries (non-critical, continuing)", batch.size(), maxRetries);
                }
                else if (stopFlag && !batch.empty())
                {
                    BOOST_LOG_TRIVIAL(warning) << std::format("markXPartDone ({} num(s)) cancelled due to shutdown", batch.size());
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
