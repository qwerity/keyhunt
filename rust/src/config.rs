//! Runtime configuration for the Rust client.

const DEFAULT_STATUS_CALLBACK_MS: u32 = 1000;
const DEFAULT_POINTS_PER_THREAD: u32 = 128;
const DEFAULT_PUBLIC_KEY_COMPRESSION: u32 = 2; // BOTH

#[derive(Debug, Clone)]
pub struct LogConfig {
    pub log_type: String, // "file" | "console"
    pub log_file_path: Option<String>,
    pub severity: u32,
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub url: String,
    pub port: String,
    pub authorisation_header: String,
    pub machine_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct HunterConfig {
    pub keys_number_to_generate: u32,
    pub ripemd160_targets_file_paths: Option<Vec<String>>,
    pub force_private_x_part: bool,
    pub private_x_part: u32,
    pub private_y_offset: u32,
    pub specific_x_values: Vec<u32>,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub hash160_targets: Option<Vec<String>>,
    pub status_callback_period_ms: u32,
    pub block_size: u32,
    pub points_per_thread: u32,
    pub keys_number_to_generate: u32,
    pub force_private_x_part: bool,
    pub private_x_part: u32,
    pub private_y_offset: u32,
    pub specific_x_values: Vec<u32>,
    pub public_key_compression_type_to_check: u32,
    pub grid_size: u32,
    pub server: Option<ServerConfig>,
    pub log: Option<LogConfig>,

    /// Test / offline mode: generate random x parts in-process instead of
    /// fetching from a server.  Range is always the full u32 space [0, u32::MAX].
    pub random_x_part_queue: bool,
}


/// Resolve effective machine_id: CLI -> VAST_CONTAINERLABEL -> gethostname() -> fallback.
fn resolve_machine_id(server: &ServerConfig) -> String {
    if let Some(ref s) = server.machine_id {
        if !s.is_empty() {
            return s.clone();
        }
    }
    if let Ok(s) = std::env::var("VAST_CONTAINERLABEL") {
        if !s.is_empty() {
            log::info!("Machine ID from VAST_CONTAINERLABEL: {}", s);
            return s;
        }
    }
    if let Ok(os) = hostname::get() {
        if let Ok(h) = os.into_string() {
            if !h.is_empty() {
                log::info!("Machine ID from gethostname(): {}", h);
                return h;
            }
        }
    }
    use std::hash::{Hash, Hasher};
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let pid = std::process::id();
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    nanos.hash(&mut hasher);
    pid.hash(&mut hasher);
    let fallback = format!("machine-{:x}", hasher.finish());
    log::info!("Machine ID using random fallback: {}", fallback);
    fallback
}

impl Config {
    pub fn new(
        hash160_targets: Vec<String>,
        status_callback_period_ms: u32,
        block_size: u32,
        points_per_thread: u32,
        keys_number_to_generate: u32,
        force_private_x_part: bool,
        private_x_part: u32,
        private_y_offset: u32,
        specific_x_values: Vec<u32>,
        public_key_compression_type_to_check: u32,
        grid_size: u32,
        server: Option<ServerConfig>,
        log: Option<LogConfig>,
        random_x_part_queue: bool,
    ) -> Self {
        let mut c = Self {
            hash160_targets: if hash160_targets.is_empty() {
                None
            } else {
                Some(hash160_targets)
            },
            status_callback_period_ms,
            block_size,
            points_per_thread,
            keys_number_to_generate,
            force_private_x_part,
            private_x_part,
            private_y_offset,
            specific_x_values,
            public_key_compression_type_to_check,
            grid_size,
            server,
            log,
            random_x_part_queue,
        };
        c.normalize();
        c
    }

    fn normalize(&mut self) {
        if self.points_per_thread == 0 {
            self.points_per_thread = DEFAULT_POINTS_PER_THREAD;
        }
        if self.status_callback_period_ms == 0 {
            self.status_callback_period_ms = DEFAULT_STATUS_CALLBACK_MS;
        }
        if self.public_key_compression_type_to_check > 2 {
            self.public_key_compression_type_to_check = DEFAULT_PUBLIC_KEY_COMPRESSION;
        }
        if let Some(ref mut server) = self.server {
            let resolved = resolve_machine_id(server);
            server.machine_id = Some(resolved);
        }
    }

    pub fn hash160_targets(&self) -> &[String] {
        static EMPTY: Vec<String> = Vec::new();
        self.hash160_targets.as_deref().unwrap_or(&EMPTY)
    }

    /// Не больше 15 с, иначе gpu_speed.txt может не обновляться (из-за конфига с огромным периодом).
    pub fn status_callback_period_ms(&self) -> u32 {
        const MAX_MS: u32 = 15_000;
        let ms = if self.status_callback_period_ms == 0 {
            DEFAULT_STATUS_CALLBACK_MS
        } else {
            self.status_callback_period_ms
        };
        ms.min(MAX_MS)
    }

    pub fn points_per_thread(&self) -> u32 {
        if self.points_per_thread == 0 {
            128
        } else {
            self.points_per_thread
        }
    }

    pub fn block_size(&self) -> u32 {
        self.block_size
    }

    pub fn grid_size(&self) -> u32 {
        self.grid_size
    }

    pub fn public_key_compression_type_to_check(&self) -> u32 {
        self.public_key_compression_type_to_check
    }

    pub fn server(&self) -> Option<&ServerConfig> {
        self.server.as_ref()
    }

    pub fn dev_mode(&self) -> bool {
        self.force_private_x_part || self.keys_number_to_generate != 0
    }

    pub fn force_private_x_part(&self) -> bool {
        self.force_private_x_part
    }

    pub fn private_x_part(&self) -> u32 {
        self.private_x_part
    }

    pub fn specific_x_values(&self) -> &[u32] {
        &self.specific_x_values
    }

    pub fn keys_number_to_generate(&self) -> u32 {
        self.keys_number_to_generate
    }

    /// True when random x part queue is enabled (offline/test mode).
    pub fn random_x_part_queue(&self) -> bool {
        self.random_x_part_queue
    }
}
