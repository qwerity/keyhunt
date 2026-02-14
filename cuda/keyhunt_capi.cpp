/**
 * C API implementation for CUDA keyhunt core. Links ECC + Hash160Lookup + CudaAtomicList.
 */
#include "keyhunt_capi.h"
#include "hash160_lookup.cuh"
#include "atomic_list.cuh"
#include "ecc.cuh"
#include "defines.h"

#include <cstdio>
#include <cstring>
#include <unordered_set>
#include <memory>
#include <vector>

#define KEYHUNT_SET_ERR(msg) do { (void)snprintf(s_keyhunt_last_error, sizeof(s_keyhunt_last_error), "%s", (msg)); } while(0)
#define KEYHUNT_SET_ERR_FMT(...) do { (void)snprintf(s_keyhunt_last_error, sizeof(s_keyhunt_last_error), __VA_ARGS__); } while(0)

static thread_local char s_keyhunt_last_error[256] = {0};

static hash160 to_hash160(const KeyhuntHash160* k)
{
    hash160 h;
    for (int i = 0; i < 5; ++i)
        h.h[i] = k->h[i];
    return h;
}

struct KeyhuntContext
{
    int device_id{0};
    std::unique_ptr<ECC> ecc;
    Hash160Lookup hash160_lookup;
    CudaAtomicList result_list;
    std::unordered_set<hash160> targets;
    uint32_t keys_per_iteration{0};

    explicit KeyhuntContext(int dev_id) : device_id(dev_id), ecc(std::make_unique<ECC>()) {}
};

extern "C" {

KeyhuntHandle keyhunt_init(int device_id)
{
    cudaError_t err = cudaSetDevice(device_id);
    if (err != cudaSuccess) {
        KEYHUNT_SET_ERR_FMT("cudaSetDevice(%d): %s", device_id, cudaGetErrorString(err));
        return nullptr;
    }
    try {
        auto* ctx = new KeyhuntContext(device_id);
        return static_cast<KeyhuntHandle>(ctx);
    } catch (const std::exception& e) {
        KEYHUNT_SET_ERR_FMT("keyhunt_init: %s", e.what());
        return nullptr;
    }
}

int keyhunt_set_params(KeyhuntHandle h, uint32_t points_per_thread, uint32_t compression_type,
                      uint32_t grid_size, uint32_t block_size)
{
    if (!h) { KEYHUNT_SET_ERR("keyhunt_set_params: null handle"); return -1; }
    auto* ctx = static_cast<KeyhuntContext*>(h);
    try {
        if (points_per_thread == 0)
            points_per_thread = 128;
        ctx->ecc->init(points_per_thread, compression_type, grid_size, block_size);
        ctx->keys_per_iteration = ctx->ecc->getKeysNumberPerIteration();
        return 0;
    } catch (const std::exception& e) {
        KEYHUNT_SET_ERR_FMT("keyhunt_set_params: %s", e.what());
        return -1;
    }
}

int keyhunt_set_targets(KeyhuntHandle h, const KeyhuntHash160* targets, size_t count)
{
    if (!h) { KEYHUNT_SET_ERR("keyhunt_set_targets: null handle"); return -1; }
    if (!targets && count > 0) { KEYHUNT_SET_ERR("keyhunt_set_targets: null targets"); return -1; }
    auto* ctx = static_cast<KeyhuntContext*>(h);
    try {
        ctx->targets.clear();
        for (size_t i = 0; i < count; ++i)
            ctx->targets.insert(to_hash160(&targets[i]));
        ctx->hash160_lookup.setTargets(ctx->targets);
        return 0;
    } catch (const std::exception& e) {
        KEYHUNT_SET_ERR_FMT("keyhunt_set_targets: %s", e.what());
        return -1;
    }
}

int keyhunt_prepare(KeyhuntHandle h)
{
    if (!h) { KEYHUNT_SET_ERR("keyhunt_prepare: null handle"); return -1; }
    auto* ctx = static_cast<KeyhuntContext*>(h);
    try {
        ctx->result_list.init(sizeof(Hash160SearchResult), 256);
        return 0;
    } catch (const std::exception& e) {
        KEYHUNT_SET_ERR_FMT("keyhunt_prepare: %s", e.what());
        return -1;
    }
}

uint32_t keyhunt_keys_per_iteration(KeyhuntHandle h)
{
    if (!h) return 0;
    return static_cast<KeyhuntContext*>(h)->keys_per_iteration;
}

int keyhunt_run_iteration(KeyhuntHandle h, uint32_t private_x_part, uint32_t iteration)
{
    if (!h) { KEYHUNT_SET_ERR("keyhunt_run_iteration: null handle"); return -1; }
    auto* ctx = static_cast<KeyhuntContext*>(h);
    try {
        ctx->ecc->generatePrivateKeysForXPerIteration(private_x_part, iteration);
        ctx->ecc->calculatePublicKeysAndCheckHash160();
        return 0;
    } catch (const std::exception& e) {
        KEYHUNT_SET_ERR_FMT("keyhunt_run_iteration: %s", e.what());
        return -1;
    }
}

uint32_t keyhunt_get_results(KeyhuntHandle h, KeyhuntSearchResult* out_results, uint32_t max_count,
                             uint32_t iteration, uint32_t private_x_part)
{
    if (!h || !out_results || max_count == 0) return 0;
    auto* ctx = static_cast<KeyhuntContext*>(h);
    const uint32_t n = ctx->result_list.size();
    if (n == 0) return 0;
    const uint32_t keys_per_iter = ctx->keys_per_iteration;
    const uint32_t to_copy = (n < max_count) ? n : max_count;

    std::vector<Hash160SearchResult> buf(to_copy);
    ctx->result_list.read(buf.data(), to_copy);
    ctx->result_list.clear();

    for (uint32_t i = 0; i < to_copy; ++i) {
        const auto& s = buf[i];
        KeyhuntSearchResult* r = &out_results[i];
        r->cuda_device_id = ctx->device_id;
        r->thread_id = s.thread;
        r->block_id = s.block;
        r->idx = s.idx;
        r->compressed = s.compressed;
        for (int j = 0; j < 5; ++j) r->digest[j] = s.digest[j];
        r->iteration = iteration;
        r->private_x_part = private_x_part;
        r->private_y_part = iteration * keys_per_iter + s.idx;
        for (int j = 0; j < 8; ++j) r->private_key[j] = s.privateKey[j];
    }
    return to_copy;
}

void keyhunt_destroy(KeyhuntHandle h)
{
    if (!h) return;
    auto* ctx = static_cast<KeyhuntContext*>(h);
    // Не вызываем cleanup() здесь — деструктор CudaAtomicList вызовет его при delete ctx
    delete ctx;
}

int keyhunt_device_count(void)
{
    int n = 0;
    cudaError_t e = cudaGetDeviceCount(&n);
    return (e == cudaSuccess) ? n : -1;
}

const char* keyhunt_last_error(void)
{
    return s_keyhunt_last_error;
}

} /* extern "C" */
