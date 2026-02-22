//! Async X part distribution: fetcher thread + mark_done batch thread.
//!
//! Two modes:
//!   • `new()` — fetches x parts from an HTTP server (production).
//!   • `new_random()` — generates random x parts in-process (test / offline mode).

use crate::http_client::HttpClient;
use crossbeam_channel::{bounded, Receiver, Sender};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

const GET_NUMBER_MAX: u32 = 1000;
const MARK_DONE_BATCH: usize = 500;
const FETCHER_SLEEP_MS: u64 = 1000;

/// Target number of x-parts to keep in the local queue (per GPU).
/// Lower = fewer "active" x on server; higher = less risk of GPU starvation.
const TARGET_QUEUE_PER_GPU: usize = 2;

/// Returns the target queue size for a given GPU count (for logging).
pub fn target_queue_size(gpu_count: usize) -> usize {
    (TARGET_QUEUE_PER_GPU * gpu_count.max(1)).max(2)
}

/// Approx. max "active" x-parts per process (channel capacity + 2 per GPU in use). For logging.
pub fn max_active_x_per_process(gpu_count: usize) -> usize {
    let g = gpu_count.max(1);
    let cap = target_queue_size(gpu_count) + g * 2;
    cap + g * 2
}

pub struct XPartManager {
    get_rx: Receiver<u32>,
    mark_tx: Sender<u32>,
    stop: Arc<AtomicBool>,
    fetcher_handle: Option<thread::JoinHandle<()>>,
    mark_handle: Option<thread::JoinHandle<()>>,
}

impl XPartManager {
    /// Production mode: fetches x parts from the HTTP server.
    /// fetcher_client: get_number only. mark_client: mark_done only (can be shared).
    pub fn new(
        fetcher_client: HttpClient,
        mark_client: std::sync::Arc<HttpClient>,
        gpu_count: usize,
    ) -> Self {
        let target_queue = target_queue_size(gpu_count);
        let cap = target_queue + gpu_count.max(1) * 2;
        let (get_tx, get_rx) = bounded::<u32>(cap);
        let (mark_tx, mark_rx) = bounded::<u32>(1024);

        let stop = Arc::new(AtomicBool::new(false));

        let stop_fetcher = Arc::clone(&stop);
        let fetcher_tx = get_tx.clone();
        let fetcher_handle = thread::spawn(move || {
            fetcher_worker(fetcher_client, fetcher_tx, target_queue, &stop_fetcher);
        });

        let stop_mark = Arc::clone(&stop);
        let mark_handle = thread::spawn(move || {
            mark_done_worker(mark_client, mark_rx, &stop_mark);
        });

        XPartManager {
            get_rx,
            mark_tx,
            stop,
            fetcher_handle: Some(fetcher_handle),
            mark_handle: Some(mark_handle),
        }
    }

    /// Test / offline mode: generates random x parts in-process, full u32 range.
    /// No server required. `mark_done` calls are silently dropped.
    ///
    /// Enable via `"randomXPartQueue": true` in config.
    pub fn new_random(gpu_count: usize) -> Self {
        let target_queue = target_queue_size(gpu_count);
        let cap = target_queue + gpu_count.max(1) * 2;
        let (get_tx, get_rx) = bounded::<u32>(cap);
        // mark_tx: discard all done notifications (no server in random mode)
        let (mark_tx, _mark_rx_drop) = bounded::<u32>(1024);

        let fetcher_handle = thread::spawn(move || {
            random_fetcher_worker(get_tx);
        });

        XPartManager {
            get_rx,
            mark_tx,
            stop: Arc::new(AtomicBool::new(false)),
            fetcher_handle: Some(fetcher_handle),
            mark_handle: None,
        }
    }

    /// Blocking: wait until a new x part is available.
    pub fn get_next_x_part(&self) -> u32 {
        let x = self.get_rx.recv().unwrap_or(0);
        log::debug!("XPartManager::get_next_x_part: x={:#x} queue_remaining={}", x, self.get_rx.len());
        x
    }

    /// Non-blocking: return `Some(x)` if a pre-fetched x part is ready, else `None`.
    /// Used to pre-generate keys for the next xpart while the current kernel runs.
    pub fn try_get_next_x_part(&self) -> Option<u32> {
        let x = self.get_rx.try_recv().ok();
        if let Some(v) = x {
            log::debug!("XPartManager::try_get_next_x_part: x={:#x} queue_remaining={}", v, self.get_rx.len());
        }
        x
    }

    pub fn mark_x_part_done_async(&self, x: u32) {
        if self.mark_tx.try_send(x).is_err() {
            log::warn!("mark_x_part_done_async: channel full, dropping x={:#x}", x);
        }
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

impl Drop for XPartManager {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        drop(self.mark_tx.clone());
        if let Some(h) = self.fetcher_handle.take() {
            let _ = h.join();
        }
        if let Some(h) = self.mark_handle.take() {
            let _ = h.join();
        }
    }
}

/// Random-queue worker: fills the channel with random u32 x values.
/// Runs until the channel receiver is dropped (XPartManager is dropped).
fn random_fetcher_worker(get_tx: Sender<u32>) {
    // xorshift64 seeded from system time — no external crate needed.
    let mut state: u64 = {
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        if t == 0 { 0xDEAD_BEEF_CAFE_1234 } else { t }
    };

    loop {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let x = state as u32;

        match get_tx.send(x) {
            Ok(()) => {}
            Err(_) => break, // receiver dropped → stop
        }
    }
}

fn fetcher_worker(
    client: HttpClient,
    get_tx: Sender<u32>,
    target_queue: usize,
    stop: &AtomicBool,
) {
    let batch = target_queue.min(GET_NUMBER_MAX as usize);
    while !stop.load(Ordering::SeqCst) {
        let queue_len = get_tx.len();
        if queue_len >= target_queue {
            thread::sleep(Duration::from_millis(FETCHER_SLEEP_MS));
            continue;
        }
        let to_fetch = (target_queue - queue_len).min(batch);
        let mut sent = 0usize;
        let mut first = 0u32;
        let mut last = 0u32;
        for _ in 0..to_fetch {
            match client.get_x_part_number() {
                Ok(n) => {
                    if get_tx.try_send(n).is_err() {
                        break;
                    }
                    if sent == 0 {
                        first = n;
                    }
                    last = n;
                    sent += 1;
                }
                Err(e) => {
                    log::error!("xpart fetcher: get_x_part_number failed: {}", e);
                    thread::sleep(Duration::from_millis(FETCHER_SLEEP_MS));
                    break;
                }
            }
        }
        if sent > 0 {
            let new_len = get_tx.len();
            log::info!("xpart fetcher: queued {} new x-parts (first={:#x} last={:#x}) queue_before={} queue_after={} target={}", sent, first, last, queue_len, new_len, target_queue);
            thread::sleep(Duration::from_millis(100));
        } else {
            thread::sleep(Duration::from_millis(FETCHER_SLEEP_MS));
        }
    }
}

fn mark_done_worker(client: std::sync::Arc<HttpClient>, rx: Receiver<u32>, stop: &AtomicBool) {
    let mut batch = Vec::with_capacity(MARK_DONE_BATCH);
    while !stop.load(Ordering::SeqCst) {
        batch.clear();
        match rx.recv_timeout(Duration::from_millis(500)) {
            Ok(n) => {
                batch.push(n);
                while batch.len() < MARK_DONE_BATCH {
                    match rx.try_recv() {
                        Ok(n) => batch.push(n),
                        Err(_) => break,
                    }
                }
                if !client.mark_x_part_done_batch(&batch) {
                    log::warn!("mark_done_worker: batch of {} x-parts failed", batch.len());
                }
            }
            Err(_) => {}
        }
    }
    while let Ok(n) = rx.try_recv() {
        batch.clear();
        batch.push(n);
        while batch.len() < MARK_DONE_BATCH {
            match rx.try_recv() {
                Ok(n) => batch.push(n),
                Err(_) => break,
            }
        }
        if !client.mark_x_part_done_batch(&batch) {
            log::warn!("mark_done_worker: final batch of {} x-parts failed", batch.len());
        }
    }
}
