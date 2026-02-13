//! Hash160 (RIPEMD-160) target loading: binary and hex files.

use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;

/// 20-byte hash as 5 x u32 (matches CUDA hash160).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Hash160(pub [u32; 5]);

const HASH160_SIZE: usize = 20;
const HEX_CHARS_PER_HASH: usize = 40;

impl Hash160 {
    /// From 20 bytes: 5 x u32 little-endian (matches C++ binary file format).
    pub fn from_bytes_le(bytes: &[u8; 20]) -> Self {
        let mut h = [0u32; 5];
        for (i, chunk) in bytes.chunks_exact(4).enumerate() {
            if i < 5 {
                h[i] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            }
        }
        Hash160(h)
    }

    /// From 40 hex chars: 5 groups of 8 hex chars -> 5 u32 (matches C++ hexToHash160).
    pub fn from_hex(hex: &str) -> Result<Self, crate::Error> {
        let hex = hex.trim();
        if hex.len() != HEX_CHARS_PER_HASH {
            return Err(crate::Error::Hash160(format!("expected 40 hex chars, got {}", hex.len())));
        }
        let mut h = [0u32; 5];
        for i in 0..5 {
            let s = &hex[i * 8..i * 8 + 8];
            h[i] = u32::from_str_radix(s, 16).map_err(|e| crate::Error::Hash160(e.to_string()))?;
        }
        Ok(Hash160(h))
    }

    /// Words for C API (host byte order; C API passes to CUDA which may swap internally).
    pub fn to_words(&self) -> [u32; 5] {
        self.0
    }

    /// 20 bytes little-endian (for writing .bin files).
    pub fn to_bytes_le(&self) -> [u8; 20] {
        let mut out = [0u8; 20];
        for (i, &w) in self.0.iter().enumerate() {
            out[i * 4..][..4].copy_from_slice(&w.to_le_bytes());
        }
        out
    }
}

/// Read binary file: 20 bytes per hash.
pub fn read_hash160_binary(path: &Path) -> Result<HashSet<Hash160>, crate::Error> {
    let mut f = File::open(path).map_err(|e| crate::Error::Io(e))?;
    let mut data = Vec::new();
    f.read_to_end(&mut data).map_err(|e| crate::Error::Io(e))?;
    if data.len() % HASH160_SIZE != 0 {
        return Err(crate::Error::Hash160("file size not multiple of 20".into()));
    }
    let mut set = HashSet::new();
    for chunk in data.chunks_exact(HASH160_SIZE) {
        let mut arr = [0u8; 20];
        arr.copy_from_slice(chunk);
        set.insert(Hash160::from_bytes_le(&arr));
    }
    Ok(set)
}

/// Read hex file: 40 hex chars per line (or contiguous).
pub fn read_hash160_hex(path: &Path) -> Result<HashSet<Hash160>, crate::Error> {
    let f = File::open(path).map_err(|e| crate::Error::Io(e))?;
    let mut set = HashSet::new();
    let reader = BufReader::new(f);
    for line in reader.lines() {
        let line = line.map_err(|e| crate::Error::Io(e))?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // Support both "40 hex chars per line" and "long concatenated hex"
        let mut i = 0;
        let bytes = line.as_bytes();
        while i + HEX_CHARS_PER_HASH <= bytes.len() {
            let s = std::str::from_utf8(&bytes[i..i + HEX_CHARS_PER_HASH])
                .map_err(|_| crate::Error::Hash160("invalid utf8 in hex".into()))?;
            set.insert(Hash160::from_hex(s)?);
            i += HEX_CHARS_PER_HASH;
        }
    }
    Ok(set)
}

/// Write hashes to binary file: 20 bytes per hash (LE).
pub fn write_hash160_binary(path: &Path, hashes: &HashSet<Hash160>) -> Result<(), crate::Error> {
    let mut f = File::create(path).map_err(crate::Error::Io)?;
    for h in hashes {
        f.write_all(&h.to_bytes_le()).map_err(crate::Error::Io)?;
    }
    Ok(())
}

/// Load all targets from list of paths. .bin = binary, else hex.
pub fn read_hash160_targets(paths: &[String]) -> Result<HashSet<Hash160>, crate::Error> {
    let mut targets = HashSet::new();
    for path in paths {
        let path = Path::new(path);
        if path.extension().map(|e| e == "bin").unwrap_or(false) {
            let set = read_hash160_binary(path)?;
            targets.extend(set);
        } else {
            let set = read_hash160_hex(path)?;
            targets.extend(set);
        }
    }
    Ok(targets)
}
