#pragma once

#include "util/common_host.h"

#include <memory>

class MasterKeysZMQClient
{
public:
    explicit MasterKeysZMQClient(const std::shared_ptr<GlobalContext> &context);
    ~MasterKeysZMQClient();

    MasterKeysZMQClient(const MasterKeysZMQClient &other) = delete;
    MasterKeysZMQClient &operator=(const MasterKeysZMQClient &other) = delete;

    void start() const;
    void stop() const;

private:
    struct Impl;
    std::unique_ptr<Impl> mImpl;
};
