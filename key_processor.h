#pragma once

#include "util/common.h"

class KeyProcessor
{
public:
    explicit KeyProcessor(const std::shared_ptr<DataQueue> &dataQueue);
    ~KeyProcessor();

    KeyProcessor(const KeyProcessor&) = delete;
    KeyProcessor& operator=(const KeyProcessor&) = delete;

    void start() const;
    void stop() const;

private:
    struct Impl;
    std::unique_ptr<Impl> mImpl;
};
