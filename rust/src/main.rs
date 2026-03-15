//! cuda-keyhunt-pvk: Rust host, CUDA core. Build CUDA lib first with CMake, then:
//!   cargo build --features cuda
//!   KEYHUNT_CUDA_LIB_DIR=../build cargo run --features cuda
//! Or run without cuda feature (no GPU).

use clap::{ArgAction, Parser};
use keyhunt_pvk::config::{Config, LogConfig, ServerConfig};
use keyhunt_pvk::hunter::run;

#[derive(Debug, Parser)]
#[command(name = "keyhunt-pvk")]
#[command(about = "Rust host for the CUDA keyhunt client")]
#[command(disable_help_flag = true)]
struct Args {
    #[arg(short = 'd', long = "data", alias = "data-file", alias = "hash160-target", required = true, num_args = 1.., value_delimiter = ',')]
    data: Vec<String>,

    #[arg(long = "status-ms", alias = "status-callback-period-ms", default_value_t = 1000)]
    status_ms: u32,

    #[arg(long = "block", alias = "block-size", default_value_t = 0)]
    block: u32,

    #[arg(long, alias = "points-per-thread", default_value_t = 8)]
    pt: u32,

    #[arg(long = "keys", alias = "keys-number-to-generate", default_value_t = 0)]
    keys: u32,

    #[arg(long = "force-x", alias = "force-private-x-part", action = ArgAction::SetTrue)]
    force_x: bool,

    #[arg(long = "x", alias = "private-x-part", default_value_t = 0)]
    x: u32,

    #[arg(long = "y-offset", alias = "private-y-offset", default_value_t = 0)]
    y_offset: u32,

    #[arg(long = "xs", alias = "specific-x-values", value_delimiter = ',')]
    xs: Vec<u32>,

    #[arg(long = "comp", alias = "public-key-compression-type-to-check", default_value_t = 2)]
    comp: u32,

    #[arg(long = "grid", alias = "grid-size", default_value_t = 0)]
    grid: u32,

    #[arg(long = "host", alias = "server-url")]
    host: Option<String>,

    #[arg(long, alias = "server-port")]
    port: Option<String>,

    #[arg(long, alias = "server-authorisation-header")]
    auth: Option<String>,

    #[arg(long = "id", alias = "machine-id")]
    id: Option<String>,

    #[arg(long = "log", alias = "log-type")]
    log: Option<String>,

    #[arg(long = "log-file", alias = "log-file-path")]
    log_file: Option<String>,

    #[arg(long = "log-severity", default_value_t = 0)]
    log_severity: u32,

    #[arg(long = "random", alias = "random-x-part-queue", action = ArgAction::SetTrue)]
    random: bool,
}

fn build_server_config(args: &Args) -> Result<Option<ServerConfig>, String> {
    let has_server_fields =
        args.host.is_some() || args.port.is_some() || args.auth.is_some() || args.id.is_some();
    if !has_server_fields {
        return Ok(None);
    }

    let url = args
        .host
        .clone()
        .ok_or_else(|| "--host is required when --port, --auth or --id is used".to_string())?;

    Ok(Some(ServerConfig {
        url,
        port: args.port.clone().unwrap_or_default(),
        authorisation_header: args.auth.clone().unwrap_or_default(),
        machine_id: args.id.clone(),
    }))
}

fn build_log_config(args: &Args) -> Option<LogConfig> {
    if args.log.is_none() && args.log_file.is_none() && args.log_severity == 0 {
        return None;
    }

    Some(LogConfig {
        log_type: args.log.clone().unwrap_or_default(),
        log_file_path: args.log_file.clone(),
        severity: args.log_severity,
    })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args_os().any(|arg| arg == "--help" || arg == "-h") {
        return Ok(());
    }

    let args = match Args::try_parse() {
        Ok(args) => args,
        Err(_) => std::process::exit(1),
    };

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

    let server = match build_server_config(&args) {
        Ok(server) => server,
        Err(_) => std::process::exit(1),
    };
    let log = build_log_config(&args);
    let config = Config::new(
        args.data,
        args.status_ms,
        args.block,
        args.pt,
        args.keys,
        args.force_x,
        args.x,
        args.y_offset,
        args.xs,
        args.comp,
        args.grid,
        server,
        log,
        args.random,
    );

    run(config, None)?;
    Ok(())
}
