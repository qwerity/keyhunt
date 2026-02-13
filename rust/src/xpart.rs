//! Async X part distribution: fetcher thread + mark_done batch thread.

use crate::http_client::HttpClient;
use crossbeam_channel::{bounded, Receiver, Sender};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

const GET_NUMBER_MAX: u32 = 1000;
const MARK_DONE_BATCH: usize = 500;
const FETCHER_SLEEP_MS: u64 = 200;

pub struct XPartManager {
    get_rx: Receiver<u32>,
    mark_tx: Sender<u32>,
    stop: AtomicBool,
    fetcher_handle: Option<thread::JoinHandle<()>>,
    mark_handle: Option<thread::JoinHandle<()>>,
}

impl XPartManager {
    /// fetcher_client: get_number only. mark_client: mark_done only (can be shared).
    pub fn new(
        fetcher_client: HttpClient,
        mark_client: std::sync::Arc<HttpClient>,
        gpu_count: usize,
    ) -> Self {
        let target_queue = (6 * gpu_count.max(1)).max(4);
        let (get_tx, get_rx) = bounded::<u32>(target_queue * 2);
        let (mark_tx, mark_rx) = bounded::<u32>(1024);

        let stop_fetcher = AtomicBool::new(false);
        let fetcher_tx = get_tx.clone();
        let fetcher_handle = thread::spawn(move || {
            fetcher_worker(
                fetcher_client,
                fetcher_tx,
                target_queue,
                &stop_fetcher,
            );
        });

        let stop_mark = AtomicBool::new(false);
        let mark_handle = thread::spawn(move || {
            mark_done_worker(mark_client, mark_rx, &stop_mark);
        });

        XPartManager {
            get_rx,
            mark_tx,
            stop: AtomicBool::new(false),
            fetcher_handle: Some(fetcher_handle),
            mark_handle: Some(mark_handle),
        }
    }

    pub fn get_next_x_part(&self) -> u32 {
        self.get_rx.recv().unwrap_or(0)
    }

    pub fn mark_x_part_done_async(&self, x: u32) {
        let _ = self.mark_tx.try_send(x);
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

fn fetcher_worker(
    client: HttpClient,
    get_tx: Sender<u32>,
    target_queue: usize,
    stop: &AtomicBool,
) {
    let batch = target_queue.min(GET_NUMBER_MAX as usize);
    while !stop.load(Ordering::SeqCst) {
        let mut sent = 0usize;
        for _ in 0..batch {
            if let Ok(n) = client.get_x_part_number() {
                if get_tx.try_send(n).is_err() {
                    break;
                }
                sent += 1;
            }
        }
        if sent == 0 {
            thread::sleep(Duration::from_millis(FETCHER_SLEEP_MS));
        } else {
            thread::sleep(Duration::from_millis(100));
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
                let _ = client.mark_x_part_done_batch(&batch);
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
        let _ = client.mark_x_part_done_batch(&batch);
    }
}
