mod pck;
mod scan;
mod upgrade;

use clap::{Parser, Subcommand};
use pck::{crypto, format_size, FileEntry};
use std::fs;
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::path::Path;

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------
#[derive(Parser)]
#[command(name = "pck-tool", version, about = "Godot PCK file parser & extractor")]
struct Cli {
    /// Path to the .pck file (or host executable with embedded PCK)
    #[arg(short, long)]
    file: Option<String>,

    /// Script encryption key (64 hex chars, 32 bytes).
    /// Defaults to all-zeros. Overridden by --detect-key when detection succeeds.
    #[arg(short, long, default_value = "0000000000000000000000000000000000000000000000000000000000000000")]
    key: String,

    /// Path to the host executable (e.g. Demo.exe) to auto-detect the
    /// embedded encryption key from. Scans .data/.rdata sections for
    /// high-entropy 32-byte sequences and verifies each against the PCK.
    #[arg(long)]
    detect_key: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// List all files in the PCK archive
    List {
        /// Show only encrypted files
        #[arg(short, long)]
        encrypted: bool,
    },
    /// Extract all files to disk
    Extract {
        /// Output directory
        #[arg(short, long, default_value = ".")]
        output: String,
        /// Only extract encrypted files
        #[arg(short, long)]
        encrypted: bool,
        /// Skip directory structure, flatten output
        #[arg(short, long)]
        flat: bool,
    },
    /// Output a single file to stdout (for piping)
    Pipe {
        /// Path inside the PCK
        path: String,
        /// Decrypt using the provided key
        #[arg(short, long)]
        decrypt: bool,
    },
    /// Check GitHub for latest release, download and install
    Upgrade,
    /// Replace binary at <OLD_PATH> with self (used internally by upgrade)
    #[command(hide = true)]
    Install {
        old_path: String,
    },
}

// ---------------------------------------------------------------------------
// Command implementations
// ---------------------------------------------------------------------------

fn read_exact(reader: &mut BufReader<&fs::File>, buf: &mut [u8]) -> io::Result<()> {
    reader.read_exact(buf)
}

fn cmd_list(entries: &[FileEntry], only_encrypted: bool) {
    let active: Vec<&FileEntry> = entries.iter().filter(|e| !e.removal).collect();
    let enc_count = active.iter().filter(|e| e.encrypted).count();
    let total_count = active.len();

    if only_encrypted {
        println!("Encrypted files ({}/{} total):", enc_count, total_count);
    } else if !active.is_empty() {
        println!(
            "Files in PCK ({} total, {} encrypted):",
            total_count, enc_count
        );
    }

    for entry in &active {
        if only_encrypted && !entry.encrypted {
            continue;
        }
        let flags = format!(
            "{}{}",
            if entry.encrypted { "E" } else { " " },
            if entry.delta { "D" } else { " " },
        );
        println!(
            "{:>10}  [{}]  {}",
            format_size(entry.size),
            flags,
            entry.path,
        );
    }

    if active.is_empty() {
        println!("  (no files)");
    }
}

fn cmd_extract(
    reader: &mut BufReader<&fs::File>,
    entries: &[FileEntry],
    key: &[u8; 32],
    output_dir: &str,
    only_encrypted: bool,
    flat: bool,
) -> io::Result<()> {
    let out_path = Path::new(output_dir);

    for entry in entries.iter().filter(|e| !e.removal) {
        if only_encrypted && !entry.encrypted {
            continue;
        }

        let rel_path = entry.path.strip_prefix("res://").unwrap_or(&entry.path);

        let file_path = if flat {
            out_path.join(
                Path::new(rel_path)
                    .file_name()
                    .unwrap_or(rel_path.as_ref()),
            )
        } else {
            out_path.join(rel_path)
        };

        if let Some(parent) = file_path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                fs::create_dir_all(parent)?;
            }
        }

        let data = pck::read_file_data(reader, entry, key)?;
        fs::write(&file_path, &data)?;
        println!(
            "  extracted: {} ({})",
            file_path.display(),
            format_size(entry.size)
        );
    }

    Ok(())
}

fn cmd_pipe(
    reader: &mut BufReader<&fs::File>,
    entries: &[FileEntry],
    key: &[u8; 32],
    path: &str,
    decrypt: bool,
) -> io::Result<()> {
    let search = path.trim_start_matches("res://");

    let entry = entries
        .iter()
        .find(|e| e.path.trim_start_matches("res://") == search)
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, format!("File not found: {}", path))
        })?;

    if entry.removal {
        return Err(io::Error::new(io::ErrorKind::NotFound, "File was removed"));
    }

    let data = if decrypt || entry.encrypted {
        pck::read_file_data(reader, entry, key)?
    } else {
        reader.seek(SeekFrom::Start(entry.offset))?;
        let mut data = vec![0u8; entry.size as usize];
        read_exact(reader, &mut data)?;
        data
    };

    io::stdout().write_all(&data)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
fn main() -> io::Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Upgrade => {
            return upgrade::upgrade();
        }
        Commands::Install { old_path } => {
            return cmd_install(old_path);
        }
        _ => {}
    }

    let file_path = cli.file.as_ref().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "--file is required for this command",
        )
    })?;

    // ----- Key detection (if requested) -------------------------------------
    let key: [u8; 32] = if let Some(host_path) = &cli.detect_key {
        detect_and_return_key(file_path, host_path)
            .unwrap_or_else(|e| {
                eprintln!("Key detection error: {}", e);
                std::process::exit(1);
            })
    } else {
        crypto::hex_to_key(&cli.key)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?
    };

    // ----- Normal operation ------------------------------------------------
    let file = match fs::File::open(file_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Error: Cannot open '{}': {}", file_path, e);
            std::process::exit(1);
        }
    };

    let mut reader = BufReader::new(&file);
    let pck_start = pck::find_pck_header(&mut reader)?;
    let result = pck::parse_header_full(&mut reader, pck_start)?;
    let entries = pck::parse_directory(
        &mut reader,
        result.header.dir_offset,
        result.header.pack_flags,
        result.file_base,
        &key,
    )?;

    let enc_dir = result.header.pack_flags & pck::PACK_DIR_ENCRYPTED != 0;
    let enc_count = entries.iter().filter(|e| e.encrypted).count();

    eprintln!(
        "PCK info: Godot {}.{}.{}, format v{}, {} files, dir_encrypted={}, file_encrypted={}",
        result.header.ver_major,
        result.header.ver_minor,
        result.header.ver_patch,
        result.header.version,
        entries.len(),
        enc_dir,
        enc_count,
    );

    match &cli.command {
        Commands::List { encrypted } => cmd_list(&entries, *encrypted),
        Commands::Extract {
            output,
            encrypted,
            flat,
        } => {
            eprintln!("Extracting to: {}", output);
            cmd_extract(&mut reader, &entries, &key, output, *encrypted, *flat)?;
            eprintln!("Done.");
        }
        Commands::Pipe { path, decrypt } => {
            cmd_pipe(&mut reader, &entries, &key, path, *decrypt)?;
        }
        Commands::Upgrade | Commands::Install { .. } => unreachable!(),
    }

    Ok(())
}

/// Attempt to auto-detect the encryption key from a host executable.
/// Opens the PCK to read the encrypted directory metadata, then scans the
/// host binary for the embedded key.
fn detect_and_return_key(file_path: &str, host_path: &str) -> io::Result<[u8; 32]> {
    eprintln!("=== Key Detection ===");
    eprintln!("PCK: {}", file_path);
    eprintln!("Host: {}", host_path);

    // 1. Open PCK, parse header, read raw encrypted directory info
    let pck_file = match fs::File::open(file_path) {
        Ok(f) => f,
        Err(e) => {
            return Err(io::Error::new(
                e.kind(),
                format!("Cannot open PCK '{}': {}", file_path, e),
            ));
        }
    };

    let mut reader = BufReader::new(&pck_file);
    let pck_start = pck::find_pck_header(&mut reader).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("PCK header not found in '{}': {}", file_path, e),
        )
    })?;
    let result = pck::parse_header_full(&mut reader, pck_start)?;

    let dir_raw = pck::read_dir_raw(
        &mut reader,
        result.header.dir_offset,
        result.header.pack_flags,
    )?;

    let dir_raw = match dir_raw {
        Some(d) => d,
        None => {
            eprintln!(
                "PCK directory is NOT encrypted (flags=0x{:08X}). No key needed.",
                result.header.pack_flags
            );
            // Use zero key — it doesn't matter since nothing is encrypted
            return Ok([0u8; 32]);
        }
    };

    eprintln!(
        "Encrypted directory: {} files, block={} bytes",
        dir_raw.file_count,
        dir_raw.block.data_len
    );

    // 2. Scan host EXE for candidate keys
    let progress = |tested: usize, total: usize| {
        eprint!("\r  Testing key candidates: {}/{}...", tested, total);
        let _ = io::stderr().flush();
    };

    let found = scan::detect_key(host_path, &dir_raw, &progress)?;

    match found {
        Some((offset, key)) => {
            eprintln!("\n  *** KEY FOUND ***");
            eprintln!("  File offset: 0x{:X} ({})", offset, offset);
            eprintln!("  Key (hex):   {}", hex::encode(key));
            eprintln!("====================");
            Ok(key)
        }
        None => {
            eprintln!("\n  Key NOT found by scanning.");
            eprintln!("  The key may be zero, or the host file may not match this PCK.");
            eprintln!("  Try specifying --key manually.");
            eprintln!("====================");
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                "Could not detect encryption key from host executable",
            ))
        }
    }
}

fn cmd_install(old_path: &str) -> io::Result<()> {
    let me = std::env::current_exe()?;
    let binary = fs::read(&me)?;
    fs::write(old_path, &binary)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(old_path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(old_path, perms)?;
    }

    // Best-effort cleanup: remove this tmp binary
    // Works on Unix (unlink running file), fails silently on Windows
    let _ = fs::remove_file(&me);

    Ok(())
}
