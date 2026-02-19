//! Hash160 (RIPEMD-160) target loading: binary and hex files.
//!
//! Uses memory-mapped I/O (same as C++ boost::iostreams::mapped_file_source)
//! and pre-sized HashSet to match C++ loading performance.

use std::collections::HashSet;
use std::fs::File;
use std::io::Write;
use std::path::Path;

use memmap2::Mmap;

/// 20-byte hash as 5 x u32 (matches CUDA hash160).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Hash160(pub [u32; 5]);

const HASH160_SIZE: usize = 20;
const HEX_CHARS_PER_HASH: usize = 40;

// ---------------------------------------------------------------------------
// Fast inline hex nibble decoder (no branch table lookup required by CPU).
// ---------------------------------------------------------------------------
#[inline(always)]
fn hex_nibble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}

/// Parse 8 raw hex ASCII bytes directly into a u32 — no String allocation.
#[inline(always)]
fn hex8_to_u32(bytes: &[u8]) -> u32 {
    (hex_nibble(bytes[0]) as u32) << 28
        | (hex_nibble(bytes[1]) as u32) << 24
        | (hex_nibble(bytes[2]) as u32) << 20
        | (hex_nibble(bytes[3]) as u32) << 16
        | (hex_nibble(bytes[4]) as u32) << 12
        | (hex_nibble(bytes[5]) as u32) << 8
        | (hex_nibble(bytes[6]) as u32) << 4
        | (hex_nibble(bytes[7]) as u32)
}

impl Hash160 {
    /// From 20 bytes: 5 x u32 little-endian (matches C++ binary file format).
    #[inline(always)]
    pub fn from_bytes_le(bytes: &[u8; 20]) -> Self {
        let mut h = [0u32; 5];
        for (i, chunk) in bytes.chunks_exact(4).enumerate() {
            h[i] = u32::from_le_bytes(chunk.try_into().unwrap());
        }
        Hash160(h)
    }

    /// From 40 raw hex ASCII bytes — zero allocation, matches C++ hexToHash160().
    #[inline(always)]
    pub fn from_hex_bytes(bytes: &[u8]) -> Result<Self, crate::Error> {
        if bytes.len() != HEX_CHARS_PER_HASH {
            return Err(crate::Error::Hash160(format!(
                "expected 40 hex bytes, got {}",
                bytes.len()
            )));
        }
        let mut h = [0u32; 5];
        for i in 0..5 {
            h[i] = hex8_to_u32(&bytes[i * 8..i * 8 + 8]);
        }
        Ok(Hash160(h))
    }

    /// From 40 hex chars string (kept for compatibility / tests).
    pub fn from_hex(hex: &str) -> Result<Self, crate::Error> {
        Self::from_hex_bytes(hex.trim().as_bytes())
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

// ---------------------------------------------------------------------------
// Binary reader — memory-mapped, pre-sized HashSet (mirrors C++).
// ---------------------------------------------------------------------------

/// Read binary file: 20 bytes per hash.
///
/// Uses mmap (zero-copy) and pre-reserves HashSet capacity, just like
/// the C++ `readSetFromHash160BinaryFile` with `boost::iostreams::mapped_file_source`.
pub fn read_hash160_binary(path: &Path) -> Result<HashSet<Hash160>, crate::Error> {
    let file = File::open(path).map_err(crate::Error::Io)?;
    // SAFETY: the file is not modified while the mmap is alive (read-only load).
    let mmap = unsafe { Mmap::map(&file) }.map_err(crate::Error::Io)?;
    let data: &[u8] = &mmap;

    if data.len() % HASH160_SIZE != 0 {
        return Err(crate::Error::Hash160("file size not multiple of 20".into()));
    }

    let count = data.len() / HASH160_SIZE;
    let mut set = HashSet::with_capacity(count); // pre-size: no rehashing

    for chunk in data.chunks_exact(HASH160_SIZE) {
        let arr: &[u8; 20] = chunk.try_into().unwrap();
        set.insert(Hash160::from_bytes_le(arr));
    }
    Ok(set)
}

// ---------------------------------------------------------------------------
// Hex reader — memory-mapped, zero-alloc hex parsing, pre-sized HashSet.
// ---------------------------------------------------------------------------

/// Read hex file: 40 hex chars per hash (one per line or concatenated).
///
/// Uses mmap and byte-level hex parsing with no String/line allocations,
/// matching C++ `readHash160HexStrFileToSet` with `boost::iostreams::mapped_file_source`.
pub fn read_hash160_hex(path: &Path) -> Result<HashSet<Hash160>, crate::Error> {
    let file = File::open(path).map_err(crate::Error::Io)?;
    // SAFETY: file is opened read-only and not modified during the mmap lifetime.
    let mmap = unsafe { Mmap::map(&file) }.map_err(crate::Error::Io)?;
    let data: &[u8] = &mmap;

    // Estimate capacity: file_size / (40 hex chars + 1 newline).
    let estimated = data.len() / (HEX_CHARS_PER_HASH + 1) + 1;
    let mut set = HashSet::with_capacity(estimated);

    let mut i = 0;
    while i < data.len() {
        // Skip newlines / whitespace (same as C++ inner while loop).
        while i < data.len()
            && matches!(data[i], b'\n' | b'\r' | b' ' | b'\t')
        {
            i += 1;
        }

        if i + HEX_CHARS_PER_HASH <= data.len() {
            let chunk = &data[i..i + HEX_CHARS_PER_HASH];
            set.insert(Hash160::from_hex_bytes(chunk)?);
            i += HEX_CHARS_PER_HASH;
        } else {
            break;
        }
    }
    Ok(set)
}

// ---------------------------------------------------------------------------
// Writer
// ---------------------------------------------------------------------------

/// Write hashes to binary file: 20 bytes per hash (LE).
pub fn write_hash160_binary(path: &Path, hashes: &HashSet<Hash160>) -> Result<(), crate::Error> {
    let mut f = File::create(path).map_err(crate::Error::Io)?;
    for h in hashes {
        f.write_all(&h.to_bytes_le()).map_err(crate::Error::Io)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Dispatcher
// ---------------------------------------------------------------------------

/// Load all targets from list of paths. `.bin` = binary, else hex.
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
