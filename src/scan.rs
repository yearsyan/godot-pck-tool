//! Scan a Godot host executable for the embedded PCK encryption key.
//!
//! The key is a 32-byte `uint8_t script_encryption_key[32]` global compiled into
//! the engine's `.data` section. We locate it by:
//! 1. Parsing the PE header to find data sections (.data, .rdata).
//! 2. Sliding-window entropy scan for 32-byte high-randomness candidates.
//! 3. Verifying each candidate by decrypting the PCK directory and checking its MD5.

use crate::pck::verify_encrypted_block;
use crate::pck::EncryptedDirRaw;

use std::io::{self, Read};

// ---------------------------------------------------------------------------
// PE parsing
// ---------------------------------------------------------------------------

/// Info about one PE section.
#[derive(Debug, Clone)]
pub struct SectionInfo {
    pub name: String,
    pub file_offset: u32,
    pub size: u32,
}

/// Parse a Windows PE (Portable Executable) file and return section headers.
fn parse_pe_sections(data: &[u8]) -> io::Result<Vec<SectionInfo>> {
    if data.len() < 64 {
        return Err(io_err("File too small for DOS header"));
    }

    // DOS header: e_lfanew at offset 0x3C
    let e_lfanew = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    if e_lfanew + 4 > data.len() {
        return Err(io_err("PE signature offset out of bounds"));
    }

    // PE signature: "PE\0\0"
    let sig = &data[e_lfanew..e_lfanew + 4];
    if sig != b"PE\0\0" {
        return Err(io_err("Not a valid PE file (missing PE signature)"));
    }

    // COFF header at e_lfanew + 4
    let coff = e_lfanew + 4;
    if coff + 20 > data.len() {
        return Err(io_err("File too small for COFF header"));
    }

    let num_sections = u16::from_le_bytes([data[coff + 2], data[coff + 3]]) as usize;
    let opt_header_size = u16::from_le_bytes([data[coff + 16], data[coff + 17]]) as usize;

    // Section headers start at: e_lfanew + 4 (signature) + 20 (COFF) + opt_header_size
    let sections_start = e_lfanew + 4 + 20 + opt_header_size;
    let section_size = 40;

    if sections_start + num_sections * section_size > data.len() {
        return Err(io_err("Section headers out of bounds"));
    }

    let mut sections = Vec::with_capacity(num_sections);
    for i in 0..num_sections {
        let sec = sections_start + i * section_size;
        // Name: 8 bytes at offset 0
        let name_end = data[sec..sec + 8]
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(8);
        let name = String::from_utf8_lossy(&data[sec..sec + name_end]).to_string();

        // VirtualSize: u32 at offset 8
        // VirtualAddress: u32 at offset 12
        // SizeOfRawData: u32 at offset 16
        // PointerToRawData: u32 at offset 20
        let size_of_raw =
            u32::from_le_bytes([data[sec + 16], data[sec + 17], data[sec + 18], data[sec + 19]]);
        let ptr_to_raw =
            u32::from_le_bytes([data[sec + 20], data[sec + 21], data[sec + 22], data[sec + 23]]);

        sections.push(SectionInfo {
            name,
            file_offset: ptr_to_raw,
            size: size_of_raw,
        });
    }

    Ok(sections)
}

// ---------------------------------------------------------------------------
// Entropy
// ---------------------------------------------------------------------------

/// Shannon entropy in bits per byte (max 8.0 for uniformly random data).
fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let n = data.len() as f64;
    let mut entropy = 0.0f64;
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / n;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Count distinct byte values in a slice.
fn distinct_count(data: &[u8]) -> usize {
    let mut seen = [false; 256];
    let mut count = 0usize;
    for &b in data {
        let idx = b as usize;
        if !seen[idx] {
            seen[idx] = true;
            count += 1;
        }
    }
    count
}

// ---------------------------------------------------------------------------
// Key scanning
// ---------------------------------------------------------------------------

const KEY_LEN: usize = 32;
const SCAN_STEP: usize = 4;
const MIN_ENTROPY: f64 = 4.0;
const MIN_DISTINCT: usize = 10;

/// Scan a byte range for 32-byte high-entropy windows.
/// Returns (file_offset, candidate_bytes, entropy).
fn scan_range(data: &[u8], base_offset: u32) -> Vec<(u64, [u8; KEY_LEN], f64)> {
    let mut candidates = Vec::new();
    let end = data.len().saturating_sub(KEY_LEN);

    let mut i = 0;
    while i <= end {
        let window = &data[i..i + KEY_LEN];
        // Quick reject: skip zeros and low-diversity windows
        if window.iter().all(|&b| b == 0) || distinct_count(window) < MIN_DISTINCT {
            i += SCAN_STEP;
            continue;
        }
        let ent = shannon_entropy(window);
        if ent >= MIN_ENTROPY {
            let mut arr = [0u8; KEY_LEN];
            arr.copy_from_slice(window);
            candidates.push((base_offset as u64 + i as u64, arr, ent));
        }
        i += SCAN_STEP;
    }

    // Sort by descending entropy (most random first — most likely a key)
    candidates.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal));
    candidates
}

/// Progress callback: called with (tested, total).
type ProgressFn<'a> = &'a dyn Fn(usize, usize);

/// Scan a host EXE for the PCK encryption key by testing candidates against the
/// encrypted directory block. Returns `(file_offset, key_bytes)` if found.
pub fn detect_key(
    host_path: &str,
    dir_raw: &EncryptedDirRaw,
    progress: ProgressFn,
) -> io::Result<Option<(u64, [u8; KEY_LEN])>> {
    // Read full host file
    let mut host_file = std::fs::File::open(host_path)
        .map_err(|e| io::Error::new(e.kind(), format!("Cannot open host file '{}': {}", host_path, e)))?;
    let mut host_data = Vec::new();
    host_file
        .read_to_end(&mut host_data)
        .map_err(|e| io::Error::new(e.kind(), format!("Cannot read host file '{}': {}", host_path, e)))?;

    eprintln!("Host file: {} ({})", host_path, format_size(host_data.len() as u64));

    // Parse PE sections
    let all_sections = parse_pe_sections(&host_data)?;
    eprintln!(
        "PE sections: {}",
        all_sections
            .iter()
            .map(|s| s.name.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );

    // Strategy: scan .data first (where Godot places `uint8_t script_encryption_key[32]`).
    // Only fall back to .rdata if .data yields nothing.
    for target in &[".data", ".rdata"] {
        let sec = match all_sections.iter().find(|s| s.name == *target) {
            Some(s) => s,
            None => continue,
        };

        let start = sec.file_offset as usize;
        let end = (sec.file_offset + sec.size) as usize;
        if end > host_data.len() {
            eprintln!("  {}: offset out of bounds, skipping", sec.name);
            continue;
        }
        let section_bytes = &host_data[start..end];
        let candidates = scan_range(section_bytes, sec.file_offset);
        eprintln!(
            "  {}: {} bytes, {} high-entropy candidates",
            sec.name,
            sec.size,
            candidates.len()
        );

        let total = candidates.len();
        if total == 0 {
            continue;
        }

        // Test candidates against encrypted directory
        for (idx, (offset, candidate, _entropy)) in candidates.iter().enumerate() {
            if idx % 10000 == 0 && idx > 0 {
                progress(idx, total);
            }
            if verify_encrypted_block(&dir_raw.block, candidate) {
                eprintln!();
                return Ok(Some((*offset, *candidate)));
            }
        }
        progress(total, total);
        eprintln!();

        if *target == ".data" {
            eprintln!("  Key not found in .data section.");
        }
    }

    eprintln!();
    Ok(None)
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    }
}

fn io_err(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_zero() {
        assert_eq!(shannon_entropy(&[0u8; 32]), 0.0);
    }

    #[test]
    fn test_entropy_max() {
        // All 256 values equally distributed: 8.0 bits/byte
        let data: Vec<u8> = (0u16..256).map(|b| b as u8).collect();
        let ent = shannon_entropy(&data);
        assert!((ent - 8.0).abs() < 0.01, "entropy = {}", ent);
    }

    #[test]
    fn test_distinct_count() {
        assert_eq!(distinct_count(&[0u8; 32]), 1);
        assert_eq!(distinct_count(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), 10);
    }
}
