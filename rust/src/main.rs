//! cuda-keyhunt-pvk: Rust host, CUDA core. Build CUDA lib first with CMake, then:
//!   cargo build --features cuda
//!   KEYHUNT_CUDA_LIB_DIR=../build cargo run --features cuda
//! Or run without cuda feature (no GPU).

use keyhunt_pvk::hunter::{run, StatusInfo};
use std::fs::File;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

const MAX_DEVICES: usize = 64;

const SPEED_FILE: &str = "gpu_speed.txt";
const WRITE_INTERVAL_MS: u64 = 1000;

/// Путь к gpu_speed.txt: текущая рабочая директория (откуда запустили), чтобы файл точно был в /workspace при cd /workspace && ./trainer_v2.
fn speed_file_path() -> std::path::PathBuf {
    std::env::current_dir()
        .ok()
        .map(|d| d.join(SPEED_FILE))
        .unwrap_or_else(|| std::path::PathBuf::from(SPEED_FILE))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::new().default_filter_or("info"))
        .format(|buf, record| {
            use std::io::Write;
            writeln!(buf, "{:5} {}", record.level(), record.args())
        })
        .init();

    let config_path = std::path::Path::new("config.json");
    if !config_path.exists() {
        eprintln!("config.json not found in current directory");
        std::process::exit(1);
    }

    // KEYHUNT_NO_SPEED_FILE=1 — полностью отключить callback и gpu_speed.txt (проверка: вернётся ли скорость к ~9 с на X).
    let no_speed_file = std::env::var("KEYHUNT_NO_SPEED_FILE").is_ok();

    if no_speed_file {
        eprintln!("KEYHUNT_NO_SPEED_FILE=1: gpu_speed.txt отключён");
        run(config_path, None)?;
    } else {
        let speed_path = speed_file_path();
        let _ = std::fs::write(&speed_path, "# GPU speed (updates every 1s)\n");

        let status_slots: Arc<Vec<Mutex<Option<StatusInfo>>>> = Arc::new(
            (0..MAX_DEVICES).map(|_| Mutex::new(None)).collect()
        );
        let stop = Arc::new(AtomicBool::new(false));

        let slots_for_writer = Arc::clone(&status_slots);
        let stop_writer = Arc::clone(&stop);
        let speed_path_writer = speed_path.clone();
        let writer_handle = thread::spawn(move || {
            thread::sleep(Duration::from_millis(2500));
            while !stop_writer.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_millis(WRITE_INTERVAL_MS));
                let mut snap: Vec<(i32, f64, f64)> = Vec::new();
                for (device_id, slot) in slots_for_writer.iter().enumerate() {
                    if let Ok(guard) = slot.try_lock() {
                        if let Some(ref i) = *guard {
                            let avg = if i.total_time_ms > 0 && i.total_keys_since_start > 0 {
                                (i.total_keys_since_start as f64 / 1e6) / (i.total_time_ms as f64 / 1000.0)
                            } else {
                                0.0
                            };
                            snap.push((device_id as i32, i.data_per_second, avg));
                        }
                    }
                }
                if snap.is_empty() { continue; }
                snap.sort_by_key(|&(d, _, _)| d);
                let total_cur: f64 = snap.iter().map(|&(_, c, _)| c).sum();
                let total_avg: f64 = snap.iter().map(|&(_, _, a)| a).sum();
                if let Ok(mut f) = File::create(&speed_path_writer) {
                    let _ = writeln!(f, "# cur = last period ({}ms), avg = since start | GPUs: {}", WRITE_INTERVAL_MS, snap.len());
                    for (device, cur, avg) in &snap {
                        let cur_s = if *cur < 0.01 { "<0.01".into() } else { format!("{:.1}", cur) };
                        let avg_s = if *avg < 0.01 { "<0.01".into() } else { format!("{:.1}", avg) };
                        let _ = writeln!(f, "GPU {}: cur {} MKey/s  avg {} MKey/s", device, cur_s, avg_s);
                    }
                    let total_cur_s = if total_cur < 0.01 { "<0.01".into() } else { format!("{:.1}", total_cur) };
                    let total_avg_s = if total_avg < 0.01 { "<0.01".into() } else { format!("{:.1}", total_avg) };
                    let _ = writeln!(f, "Total: cur {} MKey/s  avg {} MKey/s", total_cur_s, total_avg_s);
                    let _ = f.flush();
                }
            }
        });

        let status_cb: Arc<dyn Fn(StatusInfo) + Send + Sync> = Arc::new({
            let slots = Arc::clone(&status_slots);
            move |info: StatusInfo| {
                let id = info.device as usize;
                if id < slots.len() {
                    if let Ok(mut guard) = slots[id].lock() {
                        *guard = Some(info);
                    }
                }
            }
        });

        run(config_path, Some(status_cb))?;
        stop.store(true, Ordering::Relaxed);
        let _ = writer_handle.join();
    }
    Ok(())
}
