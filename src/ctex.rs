/// Godot .ctex (CompressedTexture2D) decoding.
///
/// File layout:
///   Main header (36 bytes):
///     0  magic "GST2" (4)
///     4  version: u32le
///     8  width: u32le
///     12 height: u32le
///     16 format_flags: u32le (bitfield)
///     20 mipmap_limit: i32le
///     24-35 reserved (3 × u32le)
///
///   Sub-header (16 bytes, starts at offset 36):
///     36 data_format: u32le  (0=RAW, 1=PNG, 2=WEBP, 3=BASIS)
///     40 width: u16le
///     42 height: u16le
///     44 mipmap_count: u32le
///     48 image_format: u32le (Godot Image::Format enum)

use std::fs;
use std::path::{Path, PathBuf};

/// Supported data formats in a .ctex file
#[derive(Debug, PartialEq)]
enum DataFormat {
    ImageRaw = 0,
    Png = 1,
    WebP = 2,
    BasisUniversal = 3,
}

impl DataFormat {
    fn from_u32(val: u32) -> Option<DataFormat> {
        match val {
            0 => Some(DataFormat::ImageRaw),
            1 => Some(DataFormat::Png),
            2 => Some(DataFormat::WebP),
            3 => Some(DataFormat::BasisUniversal),
            _ => None,
        }
    }
}

/// Parsed .ctex header
struct CtexHeader {
    #[allow(dead_code)]
    width: u32,
    #[allow(dead_code)]
    height: u32,
    #[allow(dead_code)]
    flags: u32,
    #[allow(dead_code)]
    mipmap_limit: i32,
    data_format: DataFormat,
    _sub_width: u16,
    _sub_height: u16,
    mipmap_count: u32,
    #[allow(dead_code)]
    img_format: u32,
}

/// Read a u32 little-endian from a byte slice at offset
fn read_u32le(data: &[u8], offset: usize) -> Option<u32> {
    let bytes: [u8; 4] = data.get(offset..offset + 4)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

/// Read a u16 little-endian from a byte slice at offset
fn read_u16le(data: &[u8], offset: usize) -> Option<u16> {
    let bytes: [u8; 2] = data.get(offset..offset + 2)?.try_into().ok()?;
    Some(u16::from_le_bytes(bytes))
}

/// Parse a .ctex file header. Returns None on invalid data.
fn parse_ctex_header(data: &[u8]) -> Option<CtexHeader> {
    if data.len() < 52 {
        return None;
    }
    if &data[0..4] != b"GST2" {
        return None;
    }

    let width = read_u32le(data, 8)?;
    let height = read_u32le(data, 12)?;
    let flags = read_u32le(data, 16)?;
    let mipmap_limit = i32::from_le_bytes(data[20..24].try_into().ok()?);
    let data_format = DataFormat::from_u32(read_u32le(data, 36)?)?;
    let sub_w = read_u16le(data, 40)?;
    let sub_h = read_u16le(data, 42)?;
    let mipmap_count = read_u32le(data, 44)?;
    let img_format = read_u32le(data, 48)?;

    Some(CtexHeader {
        width,
        height,
        flags,
        mipmap_limit,
        data_format,
        _sub_width: sub_w,
        _sub_height: sub_h,
        mipmap_count,
        img_format,
    })
}

/// Extract the first mipmap blob from the payload of a .ctex file.
/// For PNG/WEBP formats: reads [u32 size][blob], returns the blob.
/// Returns None if extraction fails.
fn extract_first_mipmap(data: &[u8], header: &CtexHeader) -> Option<Vec<u8>> {
    let payload = data.get(52..)?;

    match header.data_format {
        DataFormat::Png | DataFormat::WebP | DataFormat::BasisUniversal => {
            let mut pos = 0usize;
            // Read the first mipmap level
            let size = read_u32le(payload, pos)? as usize;
            pos += 4;
            let blob = payload.get(pos..pos + size)?.to_vec();
            Some(blob)
        }
        DataFormat::ImageRaw => {
            // VRAM-compressed format (BC7, BC3, etc.) — cannot decode without GPU lib
            None
        }
    }
}

/// Try to convert a .ctex file to PNG at the given output path.
///
/// Reads `ctex_path`, checks if the internal format is convertible (WEBP/PNG),
/// decodes the first mipmap, and writes a PNG file.
///
/// Returns `true` on successful conversion.
pub fn try_convert_ctex_to_png(ctex_path: &Path, png_path: &Path) -> bool {
    let data = match fs::read(ctex_path) {
        Ok(d) => d,
        Err(_) => return false,
    };

    let header = match parse_ctex_header(&data) {
        Some(h) => h,
        None => return false,
    };

    let blob = match extract_first_mipmap(&data, &header) {
        Some(b) => b,
        None => return false,
    };

    match header.data_format {
        DataFormat::Png => {
            // Already PNG, just copy
            if let Err(e) = fs::write(png_path, &blob) {
                eprintln!("    WARN: failed to write PNG {}: {}", png_path.display(), e);
                return false;
            }
            true
        }
        DataFormat::WebP => {
            // Decode WebP → PNG
            match image::load_from_memory(&blob) {
                Ok(img) => {
                    if let Err(e) = img.save(png_path) {
                        eprintln!(
                            "    WARN: failed to save PNG {}: {}",
                            png_path.display(),
                            e
                        );
                        return false;
                    }
                    true
                }
                Err(e) => {
                    eprintln!(
                        "    WARN: WebP decode failed for {}: {}",
                        ctex_path.display(),
                        e
                    );
                    false
                }
            }
        }
        _ => false, // BASIS / RAW — not supported
    }
}

/// Data from a parsed .import file
pub struct ImportInfo {
    pub ctex_path: String, // "res://.godot/imported/foo.png-hash.ctex"
}

/// Parse a Godot .import file (remap-only format).
///
/// Expected format:
///   [remap]
///   importer="texture"
///   type="CompressedTexture2D"
///   uid="..."
///   path="res://.godot/imported/foo.png-hash.ctex"
///   metadata={...}
///
/// Source path is derived from the .import file path itself (strip ".import").
/// Returns None if the file doesn't target a .ctex.
pub fn parse_import_file(content: &str) -> Option<ImportInfo> {
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with("path=") {
            // Extract the quoted path value
            let val = line.strip_prefix("path=").unwrap_or("");
            let val = val.trim_matches('"');
            if val.contains(".ctex") {
                return Some(ImportInfo {
                    ctex_path: val.to_string(),
                });
            }
        }
    }
    None
}

/// Walk the output directory, find .import files for ctex textures,
/// and convert the ctex back to PNG at the original source path.
///
/// The .import file maps (via `path=`) to a .ctex file in .godot/imported/.
/// The source path is derived by stripping the `.import` suffix from the import file's path.
pub fn convert_ctex_in_output(output_dir: &Path) {
    let mut converted = 0u32;
    let mut skipped = 0u32;
    let mut failed = 0u32;

    // Collect all .import files first
    let mut import_paths: Vec<PathBuf> = Vec::new();
    walk_import_files(output_dir, output_dir, &mut import_paths);

    for import_path in &import_paths {
        let content = match fs::read_to_string(import_path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let info = match parse_import_file(&content) {
            Some(i) => i,
            None => continue, // Non-texture import or already handled
        };

        // Get the ctex relative path
        let ctex_rel = info.ctex_path.trim_start_matches("res://");
        let ctex_path = output_dir.join(ctex_rel);

        if !ctex_path.exists() {
            // The ctex file might not have been extracted
            continue;
        }

        // Determine source PNG path from the .import file path
        // e.g., "addons/fmod/icons/fmod_emitter.png.import" -> "addons/fmod/icons/fmod_emitter.png"
        let import_rel = import_path
            .strip_prefix(output_dir)
            .unwrap_or(import_path);
        let import_str = import_rel.to_string_lossy();
        let source_rel = import_str
            .strip_suffix(".import")
            .unwrap_or(&import_str);
        let png_path = output_dir.join(source_rel);

        // Check if the ctex is convertible
        let ctex_data = match fs::read(&ctex_path) {
            Ok(d) => d,
            Err(_) => {
                failed += 1;
                continue;
            }
        };

        let header = match parse_ctex_header(&ctex_data) {
            Some(h) => h,
            None => continue,
        };

        // Only convert WEBP and PNG formats; skip RAW/BASIS
        match header.data_format {
            DataFormat::WebP | DataFormat::Png => {}
            _ => {
                skipped += 1;
                continue;
            }
        }

        // Ensure output parent directory exists
        if let Some(parent) = png_path.parent() {
            if !parent.exists() {
                let _ = fs::create_dir_all(parent);
            }
        }

        if try_convert_ctex_to_png(&ctex_path, &png_path) {
            converted += 1;
            println!("  untex: {} -> {}", ctex_rel, source_rel);
        } else {
            failed += 1;
        }
    }

    if converted > 0 || skipped > 0 || failed > 0 {
        eprintln!(
            "CTEX untex: {} converted, {} skipped (RAW/BASIS), {} failed",
            converted, skipped, failed
        );
    }
}

/// Recursively walk for .import files
fn walk_import_files(base_dir: &Path, current_dir: &Path, result: &mut Vec<PathBuf>) {
    let entries = match fs::read_dir(current_dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk_import_files(base_dir, &path, result);
        } else if path
            .extension()
            .and_then(|e| e.to_str())
            .map_or(false, |e| e == "import")
        {
            result.push(path);
        }
    }
}
