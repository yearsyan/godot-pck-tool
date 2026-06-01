use crate::pck::crypto;

use std::fs;
use std::io::{self, BufWriter, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};

const PACK_HEADER_MAGIC: u32 = 0x4350_4447; // "GDPC"
const PACK_FORMAT_VERSION_V3: u32 = 3;
const PACK_HEADER_UNPADDED_SIZE: u64 = 104;
const PACK_PADDING: u64 = 16;
const PACK_DIR_ENCRYPTED: u32 = 1 << 0;
const PACK_FILE_ENCRYPTED: u32 = 1 << 0;

#[derive(Debug)]
pub struct PackStats {
    pub file_count: usize,
    pub total_size: u64,
    pub encrypted: bool,
}

#[derive(Debug)]
struct SourceFile {
    path: PathBuf,
    pck_path: String,
}

#[derive(Debug)]
struct DirectoryEntry {
    path: String,
    offset: u64,
    size: u64,
    md5: [u8; 16],
    flags: u32,
}

pub fn pack_folder(
    folder: &Path,
    output: &Path,
    encrypt_key: Option<&[u8; 32]>,
) -> io::Result<PackStats> {
    if !folder.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "Folder does not exist or is not a directory: {}",
                folder.display()
            ),
        ));
    }

    if let Some(parent) = output.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            fs::create_dir_all(parent)?;
        }
    }

    let output_abs = output.canonicalize().ok();
    let mut sources = Vec::new();
    collect_files(folder, folder, output_abs.as_deref(), &mut sources)?;
    sources.sort_by(|a, b| a.pck_path.cmp(&b.pck_path));

    let file_base = aligned(PACK_HEADER_UNPADDED_SIZE, PACK_PADDING);
    let out_file = fs::File::create(output)?;
    let mut writer = BufWriter::new(out_file);
    writer.write_all(&vec![0u8; file_base as usize])?;

    let mut entries = Vec::with_capacity(sources.len());
    let mut total_size = 0u64;

    for source in sources {
        let data = fs::read(&source.path)?;
        let offset = writer.stream_position()? - file_base;
        let size = data.len() as u64;
        let md5 = md5::compute(&data).0;
        let flags = if encrypt_key.is_some() {
            PACK_FILE_ENCRYPTED
        } else {
            0
        };

        if let Some(key) = encrypt_key {
            write_encrypted_block(&mut writer, &data, key)?;
        } else {
            writer.write_all(&data)?;
        }

        total_size += size;
        entries.push(DirectoryEntry {
            path: source.pck_path,
            offset,
            size,
            md5,
            flags,
        });
    }

    let dir_offset = writer.stream_position()?;
    write_directory(&mut writer, &entries, encrypt_key)?;
    writer.seek(SeekFrom::Start(0))?;
    write_header(
        &mut writer,
        file_base,
        dir_offset,
        if encrypt_key.is_some() {
            PACK_DIR_ENCRYPTED
        } else {
            0
        },
    )?;
    writer.flush()?;

    Ok(PackStats {
        file_count: entries.len(),
        total_size,
        encrypted: encrypt_key.is_some(),
    })
}

fn collect_files(
    root: &Path,
    dir: &Path,
    output_abs: Option<&Path>,
    files: &mut Vec<SourceFile>,
) -> io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;

        if file_type.is_dir() {
            collect_files(root, &path, output_abs, files)?;
        } else if file_type.is_file() {
            if let (Some(output_abs), Ok(path_abs)) = (output_abs, path.canonicalize()) {
                if path_abs == output_abs {
                    continue;
                }
            }
            files.push(SourceFile {
                pck_path: to_pck_path(root, &path)?,
                path,
            });
        }
    }
    Ok(())
}

fn to_pck_path(root: &Path, path: &Path) -> io::Result<String> {
    let rel = path.strip_prefix(root).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Cannot build relative path for {}: {}", path.display(), e),
        )
    })?;

    let mut parts = Vec::new();
    for component in rel.components() {
        if let Component::Normal(part) = component {
            parts.push(part.to_string_lossy().into_owned());
        }
    }

    if parts.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Invalid file path inside folder: {}", path.display()),
        ));
    }

    Ok(format!("res://{}", parts.join("/")))
}

fn write_directory<W: Write>(
    writer: &mut W,
    entries: &[DirectoryEntry],
    encrypt_key: Option<&[u8; 32]>,
) -> io::Result<()> {
    let file_count = u32::try_from(entries.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Too many files to store in a PCK directory",
        )
    })?;

    write_u32(writer, file_count)?;

    let mut directory_data = Vec::new();
    for entry in entries {
        write_directory_entry(&mut directory_data, entry)?;
    }

    if let Some(key) = encrypt_key {
        write_encrypted_block(writer, &directory_data, key)?;
    } else {
        writer.write_all(&directory_data)?;
    }

    Ok(())
}

fn write_directory_entry<W: Write>(writer: &mut W, entry: &DirectoryEntry) -> io::Result<()> {
    let path_bytes = entry.path.as_bytes();
    let padded_len = aligned(path_bytes.len() as u64, 4);
    let padded_len_u32 = u32::try_from(padded_len).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("PCK path is too long: {}", entry.path),
        )
    })?;

    write_u32(writer, padded_len_u32)?;
    writer.write_all(path_bytes)?;
    for _ in path_bytes.len() as u64..padded_len {
        writer.write_all(&[0])?;
    }
    write_u64(writer, entry.offset)?;
    write_u64(writer, entry.size)?;
    writer.write_all(&entry.md5)?;
    write_u32(writer, entry.flags)?;
    Ok(())
}

fn write_encrypted_block<W: Write>(
    writer: &mut W,
    plaintext: &[u8],
    key: &[u8; 32],
) -> io::Result<()> {
    let md5 = md5::compute(plaintext).0;
    let data_len = plaintext.len() as u64;
    let cipher_len = aligned(data_len, 16);
    let mut iv = [0u8; 16];
    getrandom::getrandom(&mut iv).map_err(|e| {
        io::Error::new(io::ErrorKind::Other, format!("IV generation failed: {}", e))
    })?;

    let mut cipher = plaintext.to_vec();
    cipher.resize(cipher_len as usize, 0);
    crypto::aes256_cfb_encrypt(key, &iv, &mut cipher);

    writer.write_all(&md5)?;
    write_u64(writer, data_len)?;
    writer.write_all(&iv)?;
    writer.write_all(&cipher)?;
    Ok(())
}

fn write_header<W: Write>(
    writer: &mut W,
    file_base: u64,
    dir_offset: u64,
    pack_flags: u32,
) -> io::Result<()> {
    write_u32(writer, PACK_HEADER_MAGIC)?;
    write_u32(writer, PACK_FORMAT_VERSION_V3)?;
    write_u32(writer, 4)?;
    write_u32(writer, 0)?;
    write_u32(writer, 0)?;
    write_u32(writer, pack_flags)?;
    write_u64(writer, file_base)?;
    write_u64(writer, dir_offset)?;

    for _ in 0..16 {
        write_u32(writer, 0)?;
    }

    let padded_header_size = aligned(PACK_HEADER_UNPADDED_SIZE, PACK_PADDING);
    for _ in PACK_HEADER_UNPADDED_SIZE..padded_header_size {
        writer.write_all(&[0])?;
    }

    Ok(())
}

fn write_u32<W: Write>(writer: &mut W, value: u32) -> io::Result<()> {
    writer.write_all(&value.to_le_bytes())
}

fn write_u64<W: Write>(writer: &mut W, value: u64) -> io::Result<()> {
    writer.write_all(&value.to_le_bytes())
}

fn aligned(value: u64, alignment: u64) -> u64 {
    if value % alignment == 0 {
        value
    } else {
        value + alignment - (value % alignment)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pck;
    use std::io::BufReader;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_root(name: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "pck_tool_pack_{}_{}_{}",
            name,
            std::process::id(),
            stamp
        ))
    }

    fn read_entries(path: &Path, key: &[u8; 32]) -> (Vec<pck::FileEntry>, fs::File) {
        let file = fs::File::open(path).unwrap();
        {
            let mut reader = BufReader::new(&file);
            let pck_start = pck::find_pck_header(&mut reader).unwrap();
            let parsed = pck::parse_header_full(&mut reader, pck_start).unwrap();
            let entries = pck::parse_directory(
                &mut reader,
                parsed.header.dir_offset,
                parsed.header.pack_flags,
                parsed.file_base,
                key,
            )
            .unwrap();
            (entries, file)
        }
    }

    #[test]
    fn pack_plain_folder_round_trips() {
        let base = temp_root("plain");
        let src = base.join("src");
        let out = base.join("out.pck");
        fs::create_dir_all(src.join("nested")).unwrap();
        fs::write(src.join("hello.txt"), b"hello").unwrap();
        fs::write(src.join("nested").join("data.bin"), [0, 1, 2, 3, 4]).unwrap();

        let stats = pack_folder(&src, &out, None).unwrap();
        assert_eq!(stats.file_count, 2);
        assert_eq!(stats.total_size, 10);
        assert!(!stats.encrypted);

        let key = [0u8; 32];
        let (entries, file) = read_entries(&out, &key);
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().all(|entry| !entry.encrypted));

        let mut reader = BufReader::new(&file);
        let hello = entries
            .iter()
            .find(|entry| entry.path == "res://hello.txt")
            .unwrap();
        assert_eq!(
            pck::read_file_data(&mut reader, hello, &key).unwrap(),
            b"hello"
        );

        let data = entries
            .iter()
            .find(|entry| entry.path == "res://nested/data.bin")
            .unwrap();
        assert_eq!(
            pck::read_file_data(&mut reader, data, &key).unwrap(),
            vec![0, 1, 2, 3, 4]
        );

        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn pack_encrypted_folder_round_trips() {
        let base = temp_root("encrypted");
        let src = base.join("src");
        let out = base.join("out.pck");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("secret.txt"), b"secret payload").unwrap();

        let key = [0x42u8; 32];
        let stats = pack_folder(&src, &out, Some(&key)).unwrap();
        assert_eq!(stats.file_count, 1);
        assert_eq!(stats.total_size, 14);
        assert!(stats.encrypted);

        let (entries, file) = read_entries(&out, &key);
        assert_eq!(entries.len(), 1);
        assert!(entries[0].encrypted);
        assert_eq!(entries[0].path, "res://secret.txt");

        let mut reader = BufReader::new(&file);
        assert_eq!(
            pck::read_file_data(&mut reader, &entries[0], &key).unwrap(),
            b"secret payload"
        );

        fs::remove_dir_all(base).unwrap();
    }
}
