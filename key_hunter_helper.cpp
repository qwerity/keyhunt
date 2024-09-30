#include "key_hunter.h"

#include "util/secp256k1.h"
#include "cuda/defines.cuh"

#include <cstdint>

struct KeyHunter::Impl
{
    secp256k1::uint256 readBigInt(const uint32_t *src, const uint32_t grid, const uint32_t block, const uint32_t idx) const
    {
        uint32_t value[8];
        const uint32_t totalThreads = mGridSize * mBlockSize;
        const uint32_t threadId = grid * mBlockSize * 4 + block * 4;
        const uint32_t base = idx * mGridSize * mBlockSize * 8;

        uint32_t index = base + threadId;
        for (uint32_t k = 0; k < 4; ++k)
        {
            value[k] = src[index];
            ++index;
        }

        index = base + totalThreads * 4 + threadId;
        for (uint32_t k = 4; k < 8; ++k)
        {
            value[k] = src[index];
            ++index;
        }

        return {value, secp256k1::uint256::BigEndian};
    }

    void allocatePrivateKeysDeviceMemoryAndLoad(const thrust::host_vector<secp256k1::uint256>& privateKeys)
    {
        thrust::host_vector<uint256_t> h_privateKeys;
        h_privateKeys.resize(privateKeys.size());

        // Copy private keys to system memory buffer
        for (uint32_t grid = 0; grid < mGridSize; ++grid)
        {
            for (uint32_t block = 0; block < mBlockSize; ++block)
            {
                for (uint32_t idx = 0; idx < mPointsPerThread; ++idx)
                {
                    /// todo:
                    const int index = getIndex(grid, block, idx);
                    uint256_t::to_uint256(privateKeys[index].v, h_privateKeys[index]);
                }
            }
        }
        d_privateKeys = h_privateKeys;
    }

    void init(const uint32_t pointsPerThread, const thrust::host_vector<secp256k1::uint256> &privateKeys)
    {
        const uint32_t keysNumber = privateKeys.size();

        int minGridSize{};
        int blockSize{};
        cudaOccupancyMaxPotentialBlockSize(&minGridSize, &blockSize, multiplyStepKernel);
        std::cout << "minGridSize: " << minGridSize << ", blockSize: " << blockSize << std::endl;

        if (keysNumber < static_cast<uint32_t>(blockSize))
        {
            setPointsPerThread(1);

            mBlockSize = keysNumber;
            mGridSize = 1;
        }
        else
        {
            setPointsPerThread(pointsPerThread);

            if (keysNumber / mPointsPerThread < static_cast<uint32_t>(blockSize))
            {
                mBlockSize = keysNumber / mPointsPerThread;
            }
            else
            {
                mBlockSize = blockSize;
            }

            mGridSize = std::max(keysNumber / (blockSize * mPointsPerThread), 1U);
        }
        mKeysNumberPerIteration = mGridSize * mBlockSize * mPointsPerThread;

        std::cout << "Keys will be generated: " << mKeysNumberPerIteration << ", requested: " << keysNumber << ", skipped: " << std::abs(static_cast<int>(mKeysNumberPerIteration) - static_cast<int>(keysNumber)) << std::endl;
        std::cout << "mGridSize: " << mGridSize << ", mBlockSize: " << mBlockSize  << ", mPointsPerThread: " << mPointsPerThread << std::endl;

        // Allocate private keys on device
        allocatePrivateKeysDeviceMemoryAndLoad(privateKeys);

        // Allocate space for public keys on device
        allocatePublicKeysDeviceMemory();

        // Allocates device memory for storing the multiplication chain used in the batch inversion operation
        allocateMultChainDeviceMemory();
    }

    cudaError_t getResults(thrust::host_vector<std::pair<uint256_t, secp256k1::ecpoint>> &results) const
    {
        thrust::host_vector<uint256_t> h_publicKeysX = d_publicKeysX;
        thrust::host_vector<uint256_t> h_publicKeysY = d_publicKeysY;
        thrust::host_vector<uint256_t> h_privateKeys = d_privateKeys;

        for (uint32_t grid = 0; grid < mGridSize; ++grid)
        {
            for (uint32_t block = 0; block < mBlockSize; ++block)
            {
                for (uint32_t idx = 0; idx < mPointsPerThread; ++idx)
                {
                    const auto index = getIndex(grid, block, idx);

                    const auto x = secp256k1::uint256(h_publicKeysX[index].v, secp256k1::uint256::BigEndian);
                    const auto y = secp256k1::uint256(h_publicKeysY[index].v, secp256k1::uint256::BigEndian);

                    results.push_back({h_privateKeys[index], {x, y}});
                }
            }
        }

        return cudaSuccess;
    }

    bool selfTest(const thrust::host_vector<secp256k1::uint256> &privateKeys) const
    {
        thrust::host_vector<uint256_t> h_publicKeysX = d_publicKeysX;
        thrust::host_vector<uint256_t> h_publicKeysY = d_publicKeysY;

        bool result{true};
        for (uint32_t grid = 0; grid < mGridSize; ++grid)
        {
         for (uint32_t block = 0; block < mBlockSize; ++block)
         {
             for (uint32_t idx = 0; idx < mPointsPerThread; ++idx)
             {
                 const auto index = getIndex(grid, block, idx);
                 const secp256k1::uint256 privateKey = privateKeys[index];

                 const auto x = secp256k1::uint256(h_publicKeysX[index].v, secp256k1::uint256::BigEndian);
                 const auto y = secp256k1::uint256(h_publicKeysY[index].v, secp256k1::uint256::BigEndian);

                 const secp256k1::ecpoint pGPU(x, y);
                 if (!secp256k1::pointExists(pGPU))
                 {
                     std::cout << "Validation failed (pGPU): invalid point, for privateKey: " << privateKey.toString() << std::endl;
                     std::cout << "GPU: " << pGPU.toString(false) << std::endl;
                     result = false;
                 }

                 secp256k1::ecpoint pCPU = secp256k1::multiplyPoint(privateKey, secp256k1::G());
                 if (!secp256k1::pointExists(pCPU))
                 {
                     std::cout << "Validation failed (pCPU): invalid point, for privateKey: " << privateKey.toString() << std::endl;
                     std::cout << "CPU: " << pCPU.toString(false) << std::endl;
                     std::cout << "GPU: " << pGPU.toString(false) << std::endl;
                     result = false;
                 }

                 if (pGPU != pCPU)
                 {
                     std::cout << "Validation failed: points do not match, for privateKey: " << privateKey.toString() << std::endl;
                     std::cout << "CPU: " << pCPU.toString(false) << std::endl;
                     std::cout << "GPU: " << pGPU.toString(false) << std::endl;
                     result = false;
                 }
             }
         }
        }

        return result;
    }

    /// TODO: to be fixed
    void pushResultsToQueue() const
    {
        thrust::host_vector<std::pair<uint256_t, secp256k1::ecpoint>> results;
        // cudaCheckError(mCuECC->getResults(results));

        BOOST_LOG_TRIVIAL(info) << std::format("KeyHunter: generated {} keys", results.size());

        // to be deleted in ResultsProcessor
        auto* pairs = new Secp256k1KeyPairs;
        for (const auto &[privateKey, publicKey] : results)
        {
            const auto p = secp256k1::uint256(privateKey.v, secp256k1::uint256::BigEndian);
            pairs->emplace_back(p, publicKey);
        }

        while (!mgContext.dataQueue->push(pairs))
        {
            if (mStopFlag)
                return;

            // If the queue is full, yield to avoid busy-wait
            std::this_thread::yield();
        }
    }

    ///todo: to be fixed
    void start(const thrust::host_vector<secp256k1::uint256>& privateKeys)
    {
        setHash160Targets(mgContext.config.ripemd160TargetsFilePaths);

        // mCuECC->init(mgContext.config.pointsPerThread, privateKeys);

        mThread = std::thread([&privateKeys, this]()
                              {
                                  BOOST_LOG_TRIVIAL(trace) << "KeyHunter Thread ID: " << std::this_thread::get_id();

                                  mTimer.start();
                                  cudaCheckError(mCuECC->calculatePublicKeys());

                                  signalStatusInfo(privateKeys.size(), 1, 1, mTimer.getTime());

                                  BOOST_LOG_TRIVIAL(info) << std::format(std::locale("en_US.UTF-8"), "KeyHunter: done, generated: {:L} keys", privateKeys.size());

                                  mDone = true;
                                  pushResultsToQueue();
                              });
    }

    ///todo: to be fixed
    void startWithRandomPrivateKeys()
    {
        // start(utils::generateRandomPrivateKeys(mgContext.config.keysNumberToGenerate));
    }

    /// todo: to be fixed
    void selfTest(const uint32_t keysNumberToGenerate) const
    {
        // BOOST_LOG_TRIVIAL(info) << "KeyHunter::selfTest started";
        //
        // const thrust::host_vector<secp256k1::uint256> privateKeys = utils::generateRandomPrivateKeys(keysNumberToGenerate);
        //
        // mCuECC->init(32, privateKeys);
        //
        // cudaCheckError(mCuECC->calculatePublicKeys());
        //
        // if (mCuECC->selfTest(privateKeys))
        // {
        //     BOOST_LOG_TRIVIAL(info) << "KeyHunter::selfTest done";
        // }
        // else
        // {
        //     BOOST_LOG_TRIVIAL(info) << "KeyHunter::selfTest fails";
        // }
        //
        // thrust::host_vector<std::pair<uint256_t, secp256k1::ecpoint>> results;
        // cudaCheckError(mCuECC->getResults(results));
    }
};



/// Results_processor
void start()
{
    mThread = std::thread([this]()
    {
      BOOST_LOG_TRIVIAL(trace) << "ResultsProcessor Thread running: " << std::this_thread::get_id();

      while (!mStopFlag || !mgContext->dataQueue->empty())
      {
          Secp256k1KeyPairs* keyPairs{nullptr};

          while (!mgContext->dataQueue->pop(keyPairs))
          {
              if (mStopFlag)
                  return;

              std::this_thread::yield(); // If the queue is empty, yield to avoid busy-wait
          }

          if (!keyPairs)
          {
              BOOST_LOG_TRIVIAL(warning) << "ResultsProcessor: someone added nullptr item to queue";
              continue;
          }

          std::ranges::for_each(*keyPairs, [&](const Secp256k1KeyPair& keyPair)
          {
              constexpr bool compressed{false};
              const secp256k1::ecpoint pCPU = secp256k1::multiplyPoint(keyPair.privateKey, secp256k1::G());
              if (pCPU != keyPair.publicKey)
              {
                  BOOST_LOG_TRIVIAL(error) << "ResultsProcessor: gen key is not correct";
                  BOOST_LOG_TRIVIAL(error) << keyPair.privateKey.toString(compressed) << " " << keyPair.publicKey.toString(compressed);
              }
          });

          delete keyPairs;
      }

      BOOST_LOG_TRIVIAL(info) << "ResultsProcessor: done";
    });
}
