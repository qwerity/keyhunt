//! Results processor: consume found keys from channel, write to file, call set_found.

use crate::config::Config;
use crate::http_client::HttpClient;
use crossbeam_channel::Receiver;
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::atomic::AtomicBool;
use std::thread;
use std::time::Duration;

/// One found key result (matches C API KeyhuntSearchResult).
#[derive(Clone, Debug)]
pub struct Hash160SearchResult {
    pub cuda_device_id: i32,
    pub private_x_part: u32,
    pub private_y_part: u32,
    pub compressed: bool,
    pub digest: [u32; 5],
    pub private_key: [u32; 8],
}

const AES_KEY_HEX: &str = "CB4BBEDF03DA589798E997D86027DE755F33D226AEF90F395539DA4C08EF65B3";
const AES_IV_HEX: &str = "7E1AAE9BAE242FC510D5619B";

fn format_result(r: &Hash160SearchResult) -> String {
    let priv_hex = r.private_key.iter()
        .map(|w| format!("{:08x}", w.to_be()))
        .collect::<String>();
    let hash_hex = r.digest.iter()
        .map(|w| format!("{:08x}", w.to_be()))
        .collect::<String>();
    let comp = if r.compressed { "compressed" } else { "uncompressed" };
    format!(
        "[{}][({:>10}, {:>10}) | {:<12}] private: {}, hash160: {}",
        r.cuda_device_id,
        r.private_x_part,
        r.private_y_part,
        comp,
        priv_hex,
        hash_hex
    )
}

fn write_encrypted(path: &str, line: &str) -> bool {
    let key = match hex::decode(AES_KEY_HEX) {
        Ok(k) if k.len() == 32 => k,
        _ => return false,
    };
    let iv = match hex::decode(AES_IV_HEX) {
        Ok(i) if i.len() == 12 => i,
        _ => return false,
    };
    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes256Gcm,
    };
    let cipher = match Aes256Gcm::new_from_slice(&key) {
        Ok(c) => c,
        Err(_) => return false,
    };
    let nonce_arr: [u8; 12] = match iv.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let full = match cipher.encrypt(&nonce_arr.into(), line.as_bytes()) {
        Ok(f) => f,
        Err(_) => return false,
    };
    const TAG_SIZE: usize = 16;
    if full.len() < TAG_SIZE {
        return false;
    }
    let (ct, tag) = full.split_at(full.len() - TAG_SIZE);
    let length = (tag.len() + ct.len()) as u32;
    let mut file = match OpenOptions::new().create(true).append(true).open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    if file.write_all(&length.to_le_bytes()).is_err() { return false; }
    if file.write_all(tag).is_err() { return false; }
    if file.write_all(ct).is_err() { return false; }
    if file.flush().is_err() { return false; }
    true
}

fn append_plain(path: &str, line: &str) -> bool {
    let mut file = match OpenOptions::new().create(true).append(true).open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    if writeln!(file, "{}", line).is_err() { return false; }
    if file.flush().is_err() { return false; }
    true
}

pub fn run_results_processor(
    rx: Receiver<Hash160SearchResult>,
    config: std::sync::Arc<Config>,
    http_client: std::sync::Arc<HttpClient>,
    stop: std::sync::Arc<AtomicBool>,
) {
    thread::spawn(move || {
        while !stop.load(std::sync::atomic::Ordering::SeqCst) {
            let r = match rx.recv_timeout(Duration::from_millis(500)) {
                Ok(res) => res,
                Err(_) => continue,
            };
            let line = format_result(&r);
            let use_server = !config.dev_mode()
                && !config.force_private_x_part()
                && config.specific_x_values().is_empty();
            if use_server {
                if !http_client.set_x_part_found(r.private_x_part, r.private_y_part) {
                    log::error!("set_found failed for ({}, {}), exiting", r.private_x_part, r.private_y_part);
                    std::process::exit(1);
                }
            }
            if !write_encrypted("results.enc", &line) {
                let _ = append_plain("results.txt", &line);
            }
        }
        log::info!("ResultsProcessor: done");
    });
}
