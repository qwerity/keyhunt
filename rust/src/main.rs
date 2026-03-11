//! cuda-keyhunt-pvk: Rust host, CUDA core. Build CUDA lib first with CMake, then:
//!   cargo build --features cuda
//!   KEYHUNT_CUDA_LIB_DIR=../build cargo run --features cuda
//! Or run without cuda feature (no GPU).

use keyhunt_pvk::hunter::run;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::new().default_filter_or("info"))
        .format(|buf, record| {
            use std::io::Write;
            let now = std::time::SystemTime::now();
            let d = now.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
            let secs = d.as_secs();
            let ms = d.subsec_millis();
            let (h, m, s) = ((secs / 3600) % 24, (secs / 60) % 60, secs % 60);
            writeln!(buf, "{:02}:{:02}:{:02}.{:03} {:5} {}", h, m, s, ms, record.level(), record.args())
        })
        .init();

    let config_path = std::path::Path::new("config.json");
    if !config_path.exists() {
        eprintln!("config.json not found in current directory");
        std::process::exit(1);
    }

    run(config_path, None)?;
    Ok(())
}
