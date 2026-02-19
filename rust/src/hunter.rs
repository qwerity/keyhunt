//! Key hunter: one GPU thread — get X part, run iterations, push results.

use crate::config::Config;
use crate::hash160::{Hash160, read_hash160_targets};
use crate::results::{run_results_processor, Hash160SearchResult};
use crate::xpart::XPartManager;
use crossbeam_channel::bounded;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Instant;

#[cfg(feature = "cuda")]
use crate::cuda::{device_count, keyhunt_search_result_from_c, KeyhuntHandle, KeyhuntSearchResult};

const RESULT_QUEUE_CAP: usize = 1024;
const STATUS_LOG_INTERVAL_MS: u64 = 5000;

pub struct StatusInfo {
    pub data_per_second: f64,
    pub min_data_per_second: f64,
    pub seconds: f64,
    pub total_keys_since_start: u64,
    pub total_time_ms: u64,
    pub device: i32,
    pub device_name: String,
    pub free_device_memory: u64,
    pub total_device_memory: u64,
    pub iteration: u32,
    pub total_iterations: u32,
}

pub type StatusCallback = Arc<dyn Fn(StatusInfo) + Send + Sync>;

/// Run keyhunt: load config, targets, start results processor, spawn one thread per GPU.
pub fn run(
    config_path: &std::path::Path,
    status_callback: Option<Arc<dyn Fn(StatusInfo) + Send + Sync>>,
) -> Result<(), crate::Error> {
    let config = Config::load(config_path)?;
    let config = Arc::new(config);
    let targets_paths = config.hash160_targets();
    if targets_paths.is_empty() {
        log::warn!("No hash160 targets in config, stopping");
        return Ok(());
    }
    let targets = read_hash160_targets(targets_paths)?;
    if targets.is_empty() {
        log::warn!("Loaded 0 hash160 targets, stopping");
        return Ok(());
    }
    log::info!("Loaded {} hash160 targets", targets.len());

    #[cfg(feature = "cuda")]
    let gpu_count = device_count();
    #[cfg(not(feature = "cuda"))]
    let gpu_count = 0i32;

    if gpu_count <= 0 {
        log::info!("No CUDA devices or build without cuda feature");
        return Ok(());
    }

    let http_client: Option<Arc<crate::http_client::HttpClient>> = config.server().map(|server_cfg| {
        Arc::new(crate::http_client::HttpClient::new(server_cfg, None, None))
    });
    let use_xpart = http_client.as_ref().map_or(false, |c| {
        !config.dev_mode()
            && config.specific_x_values().is_empty()
            && c.host_alive()
    });
    if let Some(ref c) = http_client {
        log::info!("Host {} alive: {}", c.host_config(), c.host_alive());
        let need_host = !config.dev_mode() && !config.force_private_x_part() && config.specific_x_values().is_empty();
        if need_host && !c.host_alive() {
            log::error!("Host is not alive, cannot get X parts. Exiting.");
            return Err(crate::Error::Http("Host not alive".into()));
        }
    }
    if config.dev_mode() {
        log::info!("Dev mode ON [forcePrivateXPart: {} | keysNumberToGenerate: {}]",
            config.force_private_x_part(), config.keys_number_to_generate());
    }

    let xpart_manager: Option<XPartManager> = if use_xpart && http_client.is_some() {
        let fetcher = crate::http_client::HttpClient::new(
            config.server().unwrap(),
            Some(10),
            Some(10),
        );
        let mark = http_client.as_ref().unwrap().clone();
        log::info!("Initializing XPartManager for async X part distribution");
        Some(XPartManager::new(
            fetcher,
            mark,
            gpu_count as usize,
        ))
    } else {
        log::info!("XPartManager disabled (synchronous mode)");
        None
    };
    let xpart_arc: Option<Arc<XPartManager>> = xpart_manager.map(Arc::new);

    let (result_tx, result_rx) = bounded::<Hash160SearchResult>(RESULT_QUEUE_CAP);
    let stop = Arc::new(AtomicBool::new(false));
    if let Some(ref client) = http_client {
        run_results_processor(result_rx, config.clone(), client.clone(), stop.clone());
    }

    let mut handles = Vec::new();
    for device_id in 0..gpu_count {
        let config = config.clone();
        let targets = targets.clone();
        let result_tx = result_tx.clone();
        let xpart = xpart_arc.clone();
        let http = http_client.clone();
        let status_cb = status_callback.clone();
        let h = thread::spawn(move || {
            run_one_gpu(
                device_id,
                &config,
                &targets,
                result_tx,
                xpart,
                http,
                status_cb,
            );
        });
        handles.push(h);
    }
    for h in handles {
        let _ = h.join();
    }
    stop.store(true, Ordering::SeqCst);
    Ok(())
}

fn run_one_gpu(
    device_id: i32,
    config: &Config,
    targets: &HashSet<Hash160>,
    result_tx: crossbeam_channel::Sender<Hash160SearchResult>,
    xpart_manager: Option<Arc<XPartManager>>,
    http_client: Option<Arc<crate::http_client::HttpClient>>,
    status_callback: Option<StatusCallback>,
) {
    #[cfg(not(feature = "cuda"))]
    {
        let _ = (device_id, config, targets, result_tx, xpart_manager, http_client, status_callback);
        log::info!("CUDA not built in");
    }

    #[cfg(feature = "cuda")]
    {
        let mut handle = match KeyhuntHandle::init(device_id) {
            Ok(h) => h,
            Err(e) => {
                log::error!("[{}] keyhunt_init failed: {}", device_id, e);
                return;
            }
        };
        let pts = config.points_per_thread();
        let comp = config.public_key_compression_type_to_check();
        let grid = config.grid_size();
        let block = config.block_size();
        if handle.set_params(pts, comp, grid, block).is_err() {
            log::error!("[{}] set_params failed", device_id);
            return;
        }
        let target_vec: Vec<Hash160> = targets.iter().copied().collect();
        if handle.set_targets(&target_vec).is_err() {
            log::error!("[{}] set_targets failed", device_id);
            return;
        }
        if handle.prepare().is_err() {
            log::error!("[{}] prepare failed", device_id);
            return;
        }
        let keys_per_iter = handle.keys_per_iteration();
        // Как в C++: при 0 берём u32::MAX ключей (полное пространство Y для одного X), не u64::MAX
        let total_to_generate = if config.keys_number_to_generate() == 0 {
            u32::MAX as u64
        } else {
            config.keys_number_to_generate() as u64
        };
        let total_iters = (total_to_generate / keys_per_iter as u64) as u32;
        let total_iters = if total_iters == 0 { 1 } else { total_iters };
        log::info!("[{}] KeyHunter: total iterations: {}, keysPerIteration: {}",
            device_id, total_iters, keys_per_iter);

        let mut period_keys: u64 = 0;
        let mut period_ms: u64 = 0;
        let mut total_keys: u64 = 0;
        let mut total_ms: u64 = 0;
        let mut min_mkeys: f64 = 0.0;
        let mut result_buf = vec![KeyhuntSearchResult::default(); 256];
        let status_period = config.status_callback_period_ms() as u64;

        if !config.specific_x_values().is_empty() {
            for (i, &private_x) in config.specific_x_values().iter().enumerate() {
                log::info!("[{}] [{}/{}] Generating for privateXPart: {:#x}",
                    device_id, i + 1, config.specific_x_values().len(), private_x);
                run_iterations_for_x(
                    &mut handle,
                    private_x,
                    total_iters,
                    keys_per_iter,
                    &mut result_buf,
                    &result_tx,
                    targets,
                    &mut period_keys,
                    &mut period_ms,
                    &mut total_keys,
                    &mut total_ms,
                    &mut min_mkeys,
                    status_period,
                    device_id,
                    status_callback.as_deref(),
                    None, // no xpart manager for specific values
                );
            }
            return;
        }

        loop {
            let private_x = if let Some(ref xm) = xpart_manager {
                xm.get_next_x_part()
            } else if config.force_private_x_part() {
                config.private_x_part()
            } else if let Some(ref client) = http_client {
                match client.get_x_part_number() {
                    Ok(n) => n,
                    Err(e) => {
                        log::error!("[{}] get_x_part_number failed: {}, exiting", device_id, e);
                        return;
                    }
                }
            } else {
                log::error!("[{}] No server config and not force_private_x_part, exiting", device_id);
                return;
            };

            log::info!("[{}] Generating for privateXPart: {:#x}", device_id, private_x);

            run_iterations_for_x(
                &mut handle,
                private_x,
                total_iters,
                keys_per_iter,
                &mut result_buf,
                &result_tx,
                targets,
                &mut period_keys,
                &mut period_ms,
                &mut total_keys,
                &mut total_ms,
                &mut min_mkeys,
                status_period,
                device_id,
                status_callback.as_ref().map(|v| &**v),
                xpart_manager.as_deref(),
            );

            if config.force_private_x_part() {
                break;
            }
            if !config.dev_mode() && !config.force_private_x_part() {
                if let Some(ref xm) = xpart_manager {
                    xm.mark_x_part_done_async(private_x);
                }
            }
        }
    }
}

/// Run iterations for a single xpart using the double-buffer pipeline.
///
/// Timeline per iteration:
///   ┌─ pregenerate_keys(next) ──────────────┐   ← mInitStream  (async)
///   │                                        │
///   └── kernel(current) ────────────────────┘   ← mGeneratorStream (async)
///        ↓ sync_and_get_results()
///        → process results on CPU (while next keygen already running)
///
/// Returns the (xpart, first_iter) that was pre-generated but not yet launched,
/// so the caller can pass it directly to the next keyhunt_launch_kernel call.
/// Returns `None` if an error occurred.
#[cfg(feature = "cuda")]
fn run_iterations_for_x(
    handle: &mut KeyhuntHandle,
    private_x: u32,
    total_iters: u32,
    keys_per_iter: u32,
    result_buf: &mut [KeyhuntSearchResult],
    result_tx: &crossbeam_channel::Sender<Hash160SearchResult>,
    targets: &HashSet<Hash160>,
    period_keys: &mut u64,
    period_ms: &mut u64,
    total_keys: &mut u64,
    total_ms: &mut u64,
    min_mkeys: &mut f64,
    status_period_ms: u64,
    device_id: i32,
    status_cb: Option<&(dyn Fn(StatusInfo) + Send + Sync)>,
    xpart_manager: Option<&crate::xpart::XPartManager>,
) -> Option<(u32, u32)> {
    // Warm-up: generate keys for iter 0 into staging buffer, then launch kernel.
    if handle.pregenerate_keys(private_x, 0).is_err() { return None; }
    if handle.launch_kernel().is_err() { return None; }

    for iter in 0..total_iters {
        let t0 = Instant::now();

        // Determine the NEXT (xpart, iter) to pre-generate while the current kernel runs.
        // At the last iteration of this xpart, try to peek at the next xpart from the
        // pre-fetch queue — this eliminates any GPU idle gap between xpart transitions.
        let (next_x, next_iter) = if iter + 1 < total_iters {
            (private_x, iter + 1)
        } else {
            // Last iteration: try to get next xpart without blocking.
            let nx = xpart_manager
                .and_then(|xm| xm.try_get_next_x_part())
                .unwrap_or(private_x);  // fallback: re-use same xpart (caller will break if needed)
            (nx, 0u32)
        };

        // While the current kernel runs, pre-generate keys for the next iteration / xpart.
        // mInitStream and mGeneratorStream are independent → true concurrency on the GPU.
        if handle.pregenerate_keys(next_x, next_iter).is_err() { return None; }

        // Sync the kernel that was launched in the PREVIOUS loop step, then read results.
        let n = handle.sync_and_get_results(result_buf, iter, private_x);
        for i in 0..n as usize {
            let r = &result_buf[i];
            let digest_be = crate::hash160::Hash160([
                r.digest[0].to_be(),
                r.digest[1].to_be(),
                r.digest[2].to_be(),
                r.digest[3].to_be(),
                r.digest[4].to_be(),
            ]);
            if targets.contains(&digest_be) {
                let out = keyhunt_search_result_from_c(r);
                let _ = result_tx.try_send(out);
            }
        }

        // Launch the kernel for the pre-generated keys (sync keygen first internally,
        // then swap buffers and launch).  The kernel starts immediately after.
        if handle.launch_kernel().is_err() { return None; }

        let elapsed = t0.elapsed().as_millis() as u64;
        *total_keys += keys_per_iter as u64;
        *total_ms += elapsed;
        *period_keys += keys_per_iter as u64;
        *period_ms += elapsed;

        if *period_ms >= status_period_ms {
            let secs = *period_ms as f64 / 1000.0;
            let cur_mkeys = (*period_keys as f64 / secs) / 1e6;
            if *min_mkeys == 0.0 || cur_mkeys < *min_mkeys {
                *min_mkeys = cur_mkeys;
            }
            if let Some(cb) = status_cb {
                cb(StatusInfo {
                    data_per_second: cur_mkeys,
                    min_data_per_second: *min_mkeys,
                    seconds: secs,
                    total_keys_since_start: *total_keys,
                    total_time_ms: *total_ms,
                    device: device_id,
                    device_name: format!("GPU {}", device_id),
                    free_device_memory: 0,
                    total_device_memory: 0,
                    iteration: iter + 1,
                    total_iterations: total_iters,
                });
            }
            *period_keys = 0;
            *period_ms = 0;
        }
    }

    // The last kernel launched in the loop is still running.
    // Sync it and read its results before returning.
    let n = handle.sync_and_get_results(result_buf, total_iters - 1, private_x);
    for i in 0..n as usize {
        let r = &result_buf[i];
        let digest_be = crate::hash160::Hash160([
            r.digest[0].to_be(),
            r.digest[1].to_be(),
            r.digest[2].to_be(),
            r.digest[3].to_be(),
            r.digest[4].to_be(),
        ]);
        if targets.contains(&digest_be) {
            let out = keyhunt_search_result_from_c(r);
            let _ = result_tx.try_send(out);
        }
    }

    // Return the (xpart, iter) that was pre-generated into the staging buffer
    // so the outer loop can launch it directly (no extra keygen delay).
    let last_next_x = xpart_manager
        .and_then(|xm| xm.try_get_next_x_part())
        .unwrap_or(private_x);
    Some((last_next_x, 0))
}

#[cfg(feature = "cuda")]
impl Default for KeyhuntSearchResult {
    fn default() -> Self {
        KeyhuntSearchResult {
            cuda_device_id: 0,
            thread_id: 0,
            block_id: 0,
            idx: 0,
            compressed: false,
            digest: [0; 5],
            iteration: 0,
            private_x_part: 0,
            private_y_part: 0,
            private_key: [0; 8],
        }
    }
}
