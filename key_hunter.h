#pragma once

#include <thrust/host_vector.h>
#include "util/common_host.h"

class KeyHunter
{
public:
    explicit KeyHunter(const std::shared_ptr<GlobalContext>& context);
    ~KeyHunter();

    KeyHunter(KeyHunter& rhs) = delete;
    KeyHunter& operator=(KeyHunter& rhs) = delete;

    KeyHunter(KeyHunter&& rhs) noexcept;
    KeyHunter& operator=(KeyHunter&& rhs) noexcept;

    void stop() const;
    void findPublicHashWithPrivateDefinedXRandomY() const;

    [[nodiscard]] bool isDone() const;

private:
    struct Impl;
    std::unique_ptr<Impl> mImpl;
};
