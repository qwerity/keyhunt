//! Results processor: consume found keys from channel, call overfitted, log to stdout.

use crate::config::Config;
use crate::http_client::HttpClient;
use crossbeam_channel::Receiver;
use std::fs::File;
use std::io::Read;
use std::thread;

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
        "[GPU {}] ({:>10}, {:>10}) | {:<12} | private: {} hash160: {}",
        r.cuda_device_id,
        r.private_x_part,
        r.private_y_part,
        comp,
        priv_hex,
        hash_hex
    )
}

/// Read and decrypt all records from a results.enc file (same format/key as write).
pub fn read_encrypted_results(path: &str) -> Result<Vec<String>, crate::Error> {
    let key = hex::decode(AES_KEY_HEX).map_err(|e| crate::Error::Config(e.to_string()))?;
    let key: [u8; 32] = key.try_into().map_err(|_| crate::Error::Config("AES key must be 32 bytes".into()))?;
    let iv = hex::decode(AES_IV_HEX).map_err(|e| crate::Error::Config(e.to_string()))?;
    let iv: [u8; 12] = iv.try_into().map_err(|_| crate::Error::Config("AES IV must be 12 bytes".into()))?;
    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes256Gcm,
    };
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| crate::Error::Config("Aes256Gcm init".into()))?;
    let nonce = aes_gcm::Nonce::from(iv);
    let mut f = File::open(path).map_err(crate::Error::Io)?;
    const TAG_SIZE: usize = 16;
    let mut out = Vec::new();
    loop {
        let mut len_buf = [0u8; 4];
        if f.read_exact(&mut len_buf).is_err() {
            break;
        }
        let length = u32::from_le_bytes(len_buf) as usize;
        if length < TAG_SIZE {
            return Err(crate::Error::Config("invalid record length in results.enc".into()));
        }
        let mut tag = [0u8; TAG_SIZE];
        f.read_exact(&mut tag).map_err(crate::Error::Io)?;
        let mut ct = vec![0u8; length - TAG_SIZE];
        f.read_exact(&mut ct).map_err(crate::Error::Io)?;
        let mut full = ct;
        full.extend_from_slice(&tag);
        let plain = cipher.decrypt(&nonce, full.as_ref()).map_err(|e| crate::Error::Config(format!("decrypt: {}", e)))?;
        let s = String::from_utf8(plain).map_err(|e| crate::Error::Config(format!("utf8: {}", e)))?;
        out.push(s);
    }
    Ok(out)
}

pub fn run_results_processor(
    rx: Receiver<Hash160SearchResult>,
    config: std::sync::Arc<Config>,
    http_client: std::sync::Arc<HttpClient>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        loop {
            let r = match rx.recv() {
                Ok(res) => res,
                Err(_) => break,
            };
            let line = format_result(&r);
            let use_server = !config.dev_mode()
                && !config.force_private_x_part()
                && config.specific_x_values().is_empty();
            if use_server {
                if !http_client.set_x_part_found(r.private_x_part, r.private_y_part) {
                    panic!("[GPU {}] overfitted failed", r.cuda_device_id);
                }
            }
        }
        log::info!("ResultsProcessor: channel closed, all results processed");
    })
}
