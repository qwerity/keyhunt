#include "zmq_client.h"

#include <atomic>
#include <thread>
#include <zmq.h>

#include <memory>
#include <cstring>

#include <boost/log/trivial.hpp>

#include "util/utils.h"

struct MasterKeysZMQClient::Impl
{
    std::shared_ptr<GlobalContext> gContext;
    std::atomic<bool> stopFlag{false};
    std::thread receiverThread;
    void *context;
    void *subscriber;

    explicit Impl(const std::shared_ptr<GlobalContext> &globalContext) : gContext(globalContext), context(zmq_ctx_new()), subscriber(zmq_socket(context, ZMQ_SUB))
    {
        // Connect to ZeroMQ address provided by GlobalContext
        if (zmq_connect(subscriber, gContext->config.hdWallet().mnemonicMasterKeyProvider.c_str()) != 0)
        {
            throw std::runtime_error("Failed to connect to ZeroMQ server: " + std::string(zmq_strerror(zmq_errno())));
        }
        zmq_setsockopt(subscriber, ZMQ_SUBSCRIBE, "", 0);
        BOOST_LOG_TRIVIAL(info) << "MasterKeysZMQClient connected to " << gContext->config.hdWallet().mnemonicMasterKeyProvider.c_str();
    }

    ~Impl()
    {
        stop();
        zmq_close(subscriber);
        zmq_ctx_destroy(context);
    }

    Impl(const Impl &other) = delete;
    Impl &operator=(const Impl &other) = delete;

    void start()
    {
        receiverThread = std::thread([this]()
        {
            BOOST_LOG_TRIVIAL(trace) << "MasterKeysZMQClient receiving thread started: " << std::this_thread::get_id();

            HDExtendedPrivateKey frame;
            while (!stopFlag)
            {
                zmq_msg_t message;
                zmq_msg_init(&message);

                // Attempt to receive a 64-byte frame (HDExtendedPrivateKey)
                if (zmq_msg_recv(&message, subscriber, ZMQ_DONTWAIT) != -1)
                {
                    if (zmq_msg_size(&message) == sizeof(HDExtendedPrivateKey))
                    {
                        std::memcpy(&frame, zmq_msg_data(&message), sizeof(HDExtendedPrivateKey));
                        // Push frame into the global queue
                        if (!gContext->mnemonicMasterKeysQueue->push(frame))
                        {
                            BOOST_LOG_TRIVIAL(warning) << "Queue full; dropping frame";
                        }
                    }
                    else
                    {
                        BOOST_LOG_TRIVIAL(error) << "Received frame with incorrect size";
                    }
                    zmq_msg_close(&message);
                }
                else
                {
                    zmq_msg_close(&message);
                    if (zmq_errno() != EAGAIN)
                    {
                        BOOST_LOG_TRIVIAL(error) << "Failed to receive frame: " << zmq_strerror(zmq_errno());
                        break;
                    }
                    std::this_thread::yield(); // Yield to avoid busy-wait
                }
            }
            BOOST_LOG_TRIVIAL(info) << "MasterKeysZMQClient receiving thread stopping";
        });
    }

    void stop()
    {
        BOOST_LOG_TRIVIAL(trace) << "Stopping MasterKeysZMQClient";
        stopFlag = true;
        if (receiverThread.joinable())
        {
            receiverThread.join();
        }
        BOOST_LOG_TRIVIAL(trace) << "MasterKeysZMQClient stopped";
    }
};

MasterKeysZMQClient::MasterKeysZMQClient(const std::shared_ptr<GlobalContext> &context) : mImpl(std::make_unique<Impl>(context)){}
MasterKeysZMQClient::~MasterKeysZMQClient() = default;

void MasterKeysZMQClient::start() const
{
    mImpl->start();
}

void MasterKeysZMQClient::stop() const
{
    mImpl->stop();
}
