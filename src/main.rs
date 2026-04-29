mod pck;
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
    /// Path to the .pck file
    #[arg(short, long)]
    file: Option<String>,

    /// Script encryption key (64 hex chars, 32 bytes)
    #[arg(short, long, default_value = "0000000000000000000000000000000000000000000000000000000000000000")]
    key: String,

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
        io::Error::new(io::ErrorKind::InvalidInput, "--file is required for this command")
    })?;

    let key = crypto::hex_to_key(&cli.key)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

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
