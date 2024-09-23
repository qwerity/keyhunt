#pragma once

#include <memory>

#include "util/common_host.h"

class ResultsProcessor
{
public:
    explicit ResultsProcessor(const GlobalContext& context);
    ~ResultsProcessor();

    ResultsProcessor(const ResultsProcessor&) = delete;
    ResultsProcessor& operator=(const ResultsProcessor&) = delete;

    void start() const;
    void startHash160ResultsQueueProcessing() const;
    void stop() const;

private:
    struct Impl;
    std::unique_ptr<Impl> mImpl;
};
