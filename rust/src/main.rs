//! cuda-keyhunt-pvk: Rust host, CUDA core. Build CUDA lib first with CMake, then:
//!   cargo build --features cuda
//!   KEYHUNT_CUDA_LIB_DIR=../build cargo run --features cuda
//! Or run without cuda feature (no GPU).

use keyhunt_pvk::hunter::{run, StatusInfo};
use num_format::{Locale, ToFormattedString};
use std::io::Write;
use std::sync::Arc;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let config_path = std::path::Path::new("config.json");
    if !config_path.exists() {
        log::error!("config.json not found in current directory");
        std::process::exit(1);
    }

    let status_cb: Arc<dyn Fn(StatusInfo) + Send + Sync> = Arc::new(|info: StatusInfo| {
        let cur = if info.data_per_second < 0.01 { "<0.01".into() } else { format!("{:.1}", info.data_per_second) };
        let min = if info.min_data_per_second < 0.01 { "<0.01".into() } else { format!("{:.1}", info.min_data_per_second) };
        let total_sec = if info.total_time_ms > 0 && info.total_keys_since_start > 0 {
            info.total_time_ms as f64 / 1000.0
        } else {
            0.0
        };
        let avg = if total_sec > 0.0 {
            (info.total_keys_since_start as f64 / total_sec) / 1e6
        } else {
            0.0
        };
        let avg_str = if avg < 0.01 { "<0.01".into() } else { format!("{:.1}", avg) };
        let total_keys_str = info.total_keys_since_start.to_formatted_string(&Locale::en);
        let secs = info.total_time_ms / 1000;
        let line = format!(
            "{} | iter {}/{} | speed cur {} min {} avg {} MKey/s | keys {} | {}s total {}s",
            info.device_name,
            info.iteration,
            info.total_iterations,
            cur,
            min,
            avg_str,
            total_keys_str,
            info.seconds,
            secs
        );
        let _ = std::io::stderr().lock().write_fmt(format_args!("\r\x1b[K{}", line));
        let _ = std::io::stderr().flush();
    });

    run(config_path, Some(status_cb))?;
    let _ = writeln!(std::io::stderr());
    Ok(())
}
