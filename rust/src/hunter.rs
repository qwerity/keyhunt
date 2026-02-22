//! Key hunter: one GPU thread — get X part, run iterations, push results.

use crate::config::Config;
use crate::hash160::{Hash160Targets, read_hash160_targets};
use crate::results::{run_results_processor, Hash160SearchResult};
use crate::xpart::XPartManager;
use crossbeam_channel::bounded;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Instant;

#[cfg(feature = "cuda")]
use crate::cuda::{device_count, keyhunt_search_result_from_c, KeyhuntHandle, KeyhuntSearchResult};

const RESULT_QUEUE_CAP: usize = 1024;
const STATUS_LOG_INTERVAL_MS: u64 = 5000;

#[inline]
fn gpu_tag(device_id: i32) -> String {
    format!("[GPU {}]", device_id)
}

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
    let targets: Hash160Targets = read_hash160_targets(targets_paths)?;
    if targets.is_empty() {
        log::warn!("Loaded 0 hash160 targets, stopping");
        return Ok(());
    }
    log::info!("Loaded {} hash160 targets", targets.len());
    let targets = Arc::new(targets);

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

    let xpart_manager: Option<XPartManager> = if config.random_x_part_queue()
        && config.specific_x_values().is_empty()
        && !config.force_private_x_part()
    {
        // Test / offline mode: random x part queue, no server required.
        log::info!("XPartManager: random queue mode (full u32 range)");
        Some(XPartManager::new_random(gpu_count as usize))
    } else if use_xpart && http_client.is_some() {
        let fetcher = crate::http_client::HttpClient::new(
            config.server().unwrap(),
            Some(10),
            Some(10),
        );
        let mark = http_client.as_ref().unwrap().clone();
        let queue_size = crate::xpart::target_queue_size(gpu_count as usize);
        let max_active = crate::xpart::max_active_x_per_process(gpu_count as usize);
        log::info!("XPartManager: GPUs={} target_queue={} max_active_per_process≈{} (server active = sum over all processes)", gpu_count, queue_size, max_active);
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
        let targets = Arc::clone(&targets);
        let result_tx = result_tx.clone();
        let xpart = xpart_arc.clone();
        let http = http_client.clone();
        let status_cb = status_callback.clone();
        let h = thread::spawn(move || {
            run_one_gpu(
                device_id,
                &config,
                targets,
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
    targets: Arc<Hash160Targets>,
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
                log::error!("{} keyhunt_init failed: {}", gpu_tag(device_id), e);
                return;
            }
        };
        let pts = config.points_per_thread();
        let comp = config.public_key_compression_type_to_check();
        let grid = config.grid_size();
        let block = config.block_size();
        if handle.set_params(pts, comp, grid, block).is_err() {
            log::error!("{} set_params failed", gpu_tag(device_id));
            return;
        }
        if handle.set_targets(targets.as_slice()).is_err() {
            log::error!("{} set_targets failed", gpu_tag(device_id));
            return;
        }
        if handle.prepare().is_err() {
            log::error!("{} prepare failed", gpu_tag(device_id));
            return;
        }
        let keys_per_iter = handle.keys_per_iteration();
        log::info!("{} pointsPerThread={} grid={} block={} → keysPerIteration={}",
            gpu_tag(device_id), pts, grid, block, keys_per_iter);
        // Как в C++: при 0 берём u32::MAX ключей (полное пространство Y для одного X), не u64::MAX
        let total_to_generate = if config.keys_number_to_generate() == 0 {
            u32::MAX as u64
        } else {
            config.keys_number_to_generate() as u64
        };
        // Ceiling division: чтобы покрыть ровно 2^32 ключей, итераций должно быть ceil(2^32 / keys_per_iter)
        let keys_per_iter_u64 = keys_per_iter as u64;
        let total_iters = if keys_per_iter_u64 == 0 {
            1u32
        } else {
            ((total_to_generate + keys_per_iter_u64 - 1) / keys_per_iter_u64) as u32
        };
        let total_iters = total_iters.max(1);
        log::info!("{} total iterations: {}, keysPerIteration: {}",
            gpu_tag(device_id), total_iters, keys_per_iter);

        let mut period_keys: u64 = 0;
        let mut period_ms: u64 = 0;
        let mut total_keys: u64 = 0;
        let mut total_ms: u64 = 0;
        let mut min_mkeys: f64 = 0.0;
        let mut result_buf = vec![KeyhuntSearchResult::default(); 256];
        let status_period = config.status_callback_period_ms() as u64;

        if !config.specific_x_values().is_empty() {
            for (i, &private_x) in config.specific_x_values().iter().enumerate() {
                log::info!("{} [{}/{}] next x part: {:#x}",
                    gpu_tag(device_id), i + 1, config.specific_x_values().len(), private_x);
                run_iterations_for_x(
                    &mut handle,
                    private_x,
                    total_iters,
                    keys_per_iter,
                    &mut result_buf,
                    &result_tx,
                    targets.as_ref(),
                    &mut period_keys,
                    &mut period_ms,
                    &mut total_keys,
                    &mut total_ms,
                    &mut min_mkeys,
                    status_period,
                    device_id,
                    status_callback.as_deref(),
                    None,
                    false,
                );
            }
            return;
        }

        let mut pregen_x: Option<u32> = None;
        loop {
            let (private_x, x_source, skip_warmup) = if let Some(px) = pregen_x.take() {
                (px, "pregen", true)
            } else if let Some(ref xm) = xpart_manager {
                (xm.get_next_x_part(), "queue", false)
            } else if config.force_private_x_part() {
                (config.private_x_part(), "force", false)
            } else if let Some(ref client) = http_client {
                match client.get_x_part_number() {
                    Ok(n) => (n, "http", false),
                    Err(e) => {
                        log::error!("{} get_x_part_number failed: {}, exiting", gpu_tag(device_id), e);
                        return;
                    }
                }
            } else {
                log::error!("{} No server config and not force_private_x_part, exiting", gpu_tag(device_id));
                return;
            };

            log::info!("{} next x part: {:#x} (src={})", gpu_tag(device_id), private_x, x_source);

            let t_xpart = std::time::Instant::now();
            pregen_x = run_iterations_for_x(
                &mut handle,
                private_x,
                total_iters,
                keys_per_iter,
                &mut result_buf,
                &result_tx,
                targets.as_ref(),
                &mut period_keys,
                &mut period_ms,
                &mut total_keys,
                &mut total_ms,
                &mut min_mkeys,
                status_period,
                device_id,
                status_callback.as_ref().map(|v| &**v),
                xpart_manager.as_deref(),
                skip_warmup,
            );
            let elapsed_ms = t_xpart.elapsed().as_millis();
            log::info!("{} x part {:#x} done in {} ms (iters={} keys_per_iter={})",
                gpu_tag(device_id), private_x, elapsed_ms, total_iters, keys_per_iter);

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

/// Run all iterations for a single x-part. Double-buffer pipeline per iteration:
///   pregenerate_keys(iter+1) → sync(iter) → check results → launch(iter+1)
///
/// Pregen optimization: on the last iteration, if `xpart_manager` has a ready x-part,
/// pregenerate its iter=0 keys and launch while syncing current x's last kernel.
/// Returns `Some(next_x)` if pregen was done (caller should use it with `skip_warmup=true`).
///
/// `skip_warmup`: if true, iter=0 kernel is already running from a previous pregen — skip warm-up.
#[cfg(feature = "cuda")]
fn run_iterations_for_x(
    handle: &mut KeyhuntHandle,
    private_x: u32,
    total_iters: u32,
    keys_per_iter: u32,
    result_buf: &mut [KeyhuntSearchResult],
    result_tx: &crossbeam_channel::Sender<Hash160SearchResult>,
    targets: &Hash160Targets,
    period_keys: &mut u64,
    period_ms: &mut u64,
    total_keys: &mut u64,
    total_ms: &mut u64,
    min_mkeys: &mut f64,
    status_period_ms: u64,
    device_id: i32,
    status_cb: Option<&(dyn Fn(StatusInfo) + Send + Sync)>,
    xpart_manager: Option<&crate::xpart::XPartManager>,
    skip_warmup: bool,
) -> Option<u32> {
    if !skip_warmup {
        if handle.pregenerate_keys(private_x, 0).is_err() {
            log::error!("{} pregenerate_keys failed (warm-up x={:#x} iter=0)", gpu_tag(device_id), private_x);
            return None;
        }
        if handle.launch_kernel().is_err() {
            log::error!("{} launch_kernel failed (warm-up x={:#x})", gpu_tag(device_id), private_x);
            return None;
        }
    }

    let mut pregenerate_us: u64 = 0;
    let mut sync_us: u64 = 0;
    let mut cpu_check_us: u64 = 0;
    let mut launch_us: u64 = 0;
    let mut pregen_next_x: Option<u32> = None;

    for iter in 0..total_iters {
        let t0 = Instant::now();

        let is_last = iter + 1 >= total_iters;
        if !is_last {
            if handle.pregenerate_keys(private_x, iter + 1).is_err() {
                log::error!("{} pregenerate_keys failed (x={:#x} iter={})", gpu_tag(device_id), private_x, iter + 1);
                return None;
            }
        } else if let Some(nx) = xpart_manager.and_then(|xm| xm.try_get_next_x_part()) {
            log::info!("{} pregen next x part: {:#x} (prefetched from queue)", gpu_tag(device_id), nx);
            if handle.pregenerate_keys(nx, 0).is_err() {
                log::error!("{} pregenerate_keys failed (pregen x={:#x} iter=0)", gpu_tag(device_id), nx);
                return None;
            }
            pregen_next_x = Some(nx);
        }
        pregenerate_us += t0.elapsed().as_micros() as u64;

        let t_sync = Instant::now();
        let n = handle.sync_and_get_results(result_buf, iter, private_x);
        sync_us += t_sync.elapsed().as_micros() as u64;

        let t_cpu = Instant::now();
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
        cpu_check_us += t_cpu.elapsed().as_micros() as u64;

        if !is_last || pregen_next_x.is_some() {
            let t_launch = Instant::now();
            if handle.launch_kernel().is_err() {
                log::error!("{} launch_kernel failed (x={:#x} iter={})", gpu_tag(device_id), private_x, iter);
                return None;
            }
            launch_us += t_launch.elapsed().as_micros() as u64;
        }

        let elapsed_us = t0.elapsed().as_micros() as u64;
        *total_keys += keys_per_iter as u64;
        *total_ms += elapsed_us;
        *period_keys += keys_per_iter as u64;
        *period_ms += elapsed_us;

        let send_status = *period_ms >= status_period_ms * 1000 && *total_ms > 0;
        if send_status {
            let period_secs = (*period_ms as f64 / 1_000_000.0).max(0.000_001);
            let cur_mkeys = (*period_keys as f64 / period_secs) / 1e6;
            let cur_mkeys = if cur_mkeys > 100_000.0 {
                (*total_keys as f64 / 1e6) / (*total_ms as f64 / 1_000_000.0)
            } else {
                cur_mkeys
            };
            if *min_mkeys == 0.0 || cur_mkeys < *min_mkeys {
                *min_mkeys = cur_mkeys;
            }
            if let Some(cb) = status_cb {
                cb(StatusInfo {
                    data_per_second: cur_mkeys,
                    min_data_per_second: *min_mkeys,
                    seconds: *total_ms as f64 / 1_000_000.0,
                    total_keys_since_start: *total_keys,
                    total_time_ms: *total_ms / 1000,
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

    let timing_total_us = pregenerate_us + sync_us + cpu_check_us + launch_us;
    log::info!("{} x part {:#x} timing: pregen {} ms  sync {} ms  cpu {} ms  launch {} ms  total {} ms (iters={})",
        gpu_tag(device_id), private_x,
        pregenerate_us / 1000, sync_us / 1000, cpu_check_us / 1000, launch_us / 1000,
        timing_total_us / 1000, total_iters);

    pregen_next_x
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
