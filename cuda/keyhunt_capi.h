/**
 * C API for CUDA keyhunt core. Used by Rust host.
 * All types are C-compatible for FFI.
 */
#ifndef KEYHUNT_CAPI_H
#define KEYHUNT_CAPI_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Hash160: 5 x uint32_t (20 bytes), matching cuda/defines.cuh */
typedef struct KeyhuntHash160 {
    uint32_t h[5];
} KeyhuntHash160;

/* Result from GPU: matches Hash160SearchResult in defines.h */
typedef struct KeyhuntSearchResult {
    int cuda_device_id;
    uint32_t thread_id;
    uint32_t block_id;
    uint32_t idx;
    bool compressed;
    uint32_t digest[5];
    uint32_t iteration;
    uint32_t private_x_part;
    uint32_t private_y_part;
    uint32_t private_key[8];
} KeyhuntSearchResult;

/* Opaque handle for one GPU context */
typedef void* KeyhuntHandle;

/**
 * Initialize CUDA for the given device and create a keyhunt context.
 * Returns NULL on failure.
 */
KeyhuntHandle keyhunt_init(int device_id);

/**
 * Set run parameters. Call before set_targets.
 * compression_type: 0=compressed, 1=uncompressed, 2=both
 */
int keyhunt_set_params(KeyhuntHandle h, uint32_t points_per_thread, uint32_t compression_type,
                       uint32_t grid_size, uint32_t block_size);

/**
 * Set hash160 targets. targets = array of KeyhuntHash160, count = number of elements.
 */
int keyhunt_set_targets(KeyhuntHandle h, const KeyhuntHash160* targets, size_t count);

/**
 * Prepare for iterations (allocates result buffer, etc.). Call after set_targets.
 */
int keyhunt_prepare(KeyhuntHandle h);

/**
 * Number of keys generated per iteration.
 */
uint32_t keyhunt_keys_per_iteration(KeyhuntHandle h);

/**
 * Run one iteration: generate private keys for (private_x_part, iteration) and check hash160.
 */
int keyhunt_run_iteration(KeyhuntHandle h, uint32_t private_x_part, uint32_t iteration);

/**
 * Get results from last run_iteration. out_results must have space for at least max_count results.
 * iteration and private_x_part are used to fill result fields. Returns number of results written.
 */
uint32_t keyhunt_get_results(KeyhuntHandle h, KeyhuntSearchResult* out_results, uint32_t max_count,
                             uint32_t iteration, uint32_t private_x_part);

/**
 * Destroy context and release GPU resources.
 */
void keyhunt_destroy(KeyhuntHandle h);

/**
 * Get number of CUDA devices.
 */
int keyhunt_device_count(void);

/**
 * Get last error string (thread-local). Valid until next call to any keyhunt_* function on this thread.
 */
const char* keyhunt_last_error(void);

#ifdef __cplusplus
}
#endif

#endif /* KEYHUNT_CAPI_H */
