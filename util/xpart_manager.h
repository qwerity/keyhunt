#pragma once

#include <cstdint>
#include <memory>
#include <thread>
#include <atomic>
#include <queue>
#include <mutex>
#include <condition_variable>
#include "http_client.h"

class XPartManager
{
public:
    explicit XPartManager(std::shared_ptr<HttpClient> httpClient, bool randomMode, size_t gpuCount = 1);
    ~XPartManager();

    XPartManager(const XPartManager&) = delete;
    XPartManager& operator=(const XPartManager&) = delete;

    // Get next X part (non-blocking if pre-fetched, blocking if queue is empty)
    uint32_t getNextXPart();

    // Mark X part as done (async, non-blocking)
    void markXPartDoneAsync(uint32_t xPart);

    // Stop the manager
    void stop();

private:
    struct Impl;
    std::unique_ptr<Impl> mImpl;
};
