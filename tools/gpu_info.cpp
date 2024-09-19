#include <util/cuda_util.h>

int main()
{
    const auto deviceInfoList = cu::getDevices();
    for (const auto& deviceInfo : deviceInfoList)
    {
        cu:printDeviceInfo(deviceInfo);
    }

    return 0;
}