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
 * generator_mode: 1=generatePrivateKeyBase, 2=generatePrivateKeyBase2
 */
int keyhunt_set_params(KeyhuntHandle h, uint32_t points_per_thread, uint32_t compression_type,
                       uint32_t generator_mode, uint32_t grid_size, uint32_t block_size);

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
 * BLOCKING — returns only after GPU kernel completes.
 */
int keyhunt_run_iteration(KeyhuntHandle h, uint32_t private_x_part, uint32_t iteration);

/**
 * Get results from last run_iteration. out_results must have space for at least max_count results.
 * iteration and private_x_part are used to fill result fields. Returns number of results written.
 */
uint32_t keyhunt_get_results(KeyhuntHandle h, KeyhuntSearchResult* out_results, uint32_t max_count,
                             uint32_t iteration, uint32_t private_x_part);

/* ---- Double-buffer pipeline API (zero GPU idle between xpart transitions) ----
 *
 * Typical call sequence:
 *
 *   keyhunt_pregenerate_keys(h, x, 0);     // async key-gen into staging buffer
 *   keyhunt_launch_kernel(h);              // sync key-gen, swap, launch kernel async
 *   loop:
 *     keyhunt_pregenerate_keys(h, x_next, iter_next); // overlap with running kernel
 *     keyhunt_sync_and_get_results(h, out, max, iter, x);  // sync kernel + read
 *     keyhunt_launch_kernel(h);            // sync key-gen, swap, launch next kernel
 */

/**
 * Step 1: start generating private keys for (x, iter) into the staging buffer,
 * asynchronously on the init stream.  Returns immediately; does NOT block.
 */
int keyhunt_pregenerate_keys(KeyhuntHandle h, uint32_t private_x_part, uint32_t iteration);

/**
 * Step 2: synchronize the init stream (wait for pregenerate_keys to finish),
 * promote staging→current buffer, then launch the hash-check kernel asynchronously.
 * Returns immediately; kernel runs in background.
 */
int keyhunt_launch_kernel(KeyhuntHandle h);

/**
 * Step 3: synchronize the generator stream (wait for kernel launched by launch_kernel),
 * then read results.  Returns number of results written into out_results.
 * iteration and private_x_part label the results for the caller.
 */
uint32_t keyhunt_sync_and_get_results(KeyhuntHandle h, KeyhuntSearchResult* out_results,
                                      uint32_t max_count, uint32_t iteration,
                                      uint32_t private_x_part);

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
