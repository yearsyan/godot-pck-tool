pub mod crypto;

use std::fs;
use std::io::{self, BufReader, Read, Seek, SeekFrom};

use crypto::aes256_cfb_decrypt;

// ----- Constants -----------------------------------------------------------

const PACK_HEADER_MAGIC: u32 = 0x4350_4447; // "GDPC"

const PACK_FORMAT_VERSION_V3: u32 = 3;

pub const PACK_DIR_ENCRYPTED: u32 = 1 << 0;
const PACK_FILE_ENCRYPTED: u32 = 1 << 0;
const PACK_FILE_REMOVAL: u32 = 1 << 1;
const PACK_FILE_DELTA: u32 = 1 << 2;

// ----- Primitives ----------------------------------------------------------

fn read_u32_be(reader: &mut BufReader<&fs::File>) -> io::Result<u32> {
    let mut buf = [0u8; 4];
    reader.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

fn read_u64_be(reader: &mut BufReader<&fs::File>) -> io::Result<u64> {
    let mut buf = [0u8; 8];
    reader.read_exact(&mut buf)?;
    Ok(u64::from_le_bytes(buf))
}

fn reader_u32<R: Read>(r: &mut R) -> io::Result<u32> {
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

fn reader_u64<R: Read>(r: &mut R) -> io::Result<u64> {
    let mut buf = [0u8; 8];
    r.read_exact(&mut buf)?;
    Ok(u64::from_le_bytes(buf))
}

// ----- Types ---------------------------------------------------------------

#[derive(Debug)]
pub struct PckHeader {
    pub version: u32,
    pub ver_major: u32,
    pub ver_minor: u32,
    pub ver_patch: u32,
    pub pack_flags: u32,
    pub dir_offset: u64,
}

#[derive(Debug)]
pub struct PckParseResult {
    pub header: PckHeader,
    pub file_base: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct PckLocation {
    pub start: u64,
    pub size: u64,
    pub embedded: bool,
}

#[derive(Debug, Clone)]
pub struct FileEntry {
    pub path: String,
    pub offset: u64,
    pub size: u64,
    #[allow(dead_code)]
    pub md5: [u8; 16],
    pub encrypted: bool,
    pub removal: bool,
    pub delta: bool,
}

// ----- Header --------------------------------------------------------------

/// Find PCK header. Tries start-of-file, then embedded trailer at end.
pub fn find_pck_header(reader: &mut BufReader<&fs::File>) -> io::Result<i64> {
    let location = locate_pck(reader)?;
    i64::try_from(location.start).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "PCK header offset does not fit in i64",
        )
    })
}

/// Locate PCK bytes in a standalone .pck or a host executable with an embedded PCK.
pub fn locate_pck(reader: &mut BufReader<&fs::File>) -> io::Result<PckLocation> {
    let file_len = reader.seek(SeekFrom::End(0))?;

    // Standalone PCK: start of file
    if file_len >= 4 {
        reader.seek(SeekFrom::Start(0))?;
        let magic = read_u32_be(reader)?;
        if magic == PACK_HEADER_MAGIC {
            return Ok(PckLocation {
                start: 0,
                size: file_len,
                embedded: false,
            });
        }
    }

    // Embedded trailer: [pck_size: u64 | GDPC: u32] at end of file
    if file_len >= 12 {
        reader.seek(SeekFrom::Start(file_len - 4))?;
        let magic = read_u32_be(reader)?;
        if magic == PACK_HEADER_MAGIC {
            reader.seek(SeekFrom::Start(file_len - 12))?;
            let pck_size = read_u64_be(reader)?;
            if pck_size >= 4 && pck_size <= file_len - 12 {
                let pck_start = file_len - 12 - pck_size;
                reader.seek(SeekFrom::Start(pck_start))?;
                let magic = read_u32_be(reader)?;
                if magic == PACK_HEADER_MAGIC {
                    return Ok(PckLocation {
                        start: pck_start,
                        size: pck_size,
                        embedded: true,
                    });
                }
            }
        }
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "PCK header not found",
    ))
}

pub fn parse_header_full(
    reader: &mut BufReader<&fs::File>,
    pck_start_pos: i64,
) -> io::Result<PckParseResult> {
    reader.seek(SeekFrom::Start(pck_start_pos as u64 + 4))?; // skip magic
    let version = read_u32_be(reader)?;
    let ver_major = read_u32_be(reader)?;
    let ver_minor = read_u32_be(reader)?;
    let ver_patch = read_u32_be(reader)?;
    let pack_flags = read_u32_be(reader)?;
    let file_base_raw = read_u64_be(reader)?;

    if version != PACK_FORMAT_VERSION_V3 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Unsupported PCK format version: {}", version),
        ));
    }

    let dir_offset_raw = read_u64_be(reader)?;
    let pck_start = pck_start_pos as u64;

    Ok(PckParseResult {
        header: PckHeader {
            version,
            ver_major,
            ver_minor,
            ver_patch,
            pack_flags,
            dir_offset: dir_offset_raw + pck_start,
        },
        file_base: file_base_raw + pck_start,
    })
}

// ----- Encrypted block -----------------------------------------------------

struct EncryptedBlock {
    data: Vec<u8>,
}

/// Raw encrypted block data read from the file — BEFORE decryption.
/// Used for key-guessing: we read this once, then try multiple keys against it.
#[derive(Debug, Clone)]
pub struct RawEncryptedBlock {
    pub md5_expected: [u8; 16],
    pub data_len: u64,
    pub iv: [u8; 16],
    pub cipher: Vec<u8>,
}

/// Read the raw encrypted region from the current reader position.
/// Returns the metadata and ciphertext needed for later decryption attempts.
fn read_raw_encrypted_block(reader: &mut BufReader<&fs::File>) -> io::Result<RawEncryptedBlock> {
    let mut md5_expected = [0u8; 16];
    reader.read_exact(&mut md5_expected)?;

    let data_len = read_u64_be(reader)?;

    let mut iv = [0u8; 16];
    reader.read_exact(&mut iv)?;

    let cipher_len = if data_len % 16 == 0 {
        data_len
    } else {
        data_len + 16 - (data_len % 16)
    };

    let mut cipher = vec![0u8; cipher_len as usize];
    reader.read_exact(&mut cipher)?;

    Ok(RawEncryptedBlock {
        md5_expected,
        data_len,
        iv,
        cipher,
    })
}

/// Try to decrypt and verify a raw encrypted block with the given key.
/// Returns the decrypted data on success, or an error.
fn decrypt_raw_block(raw: &RawEncryptedBlock, key: &[u8; 32]) -> io::Result<Vec<u8>> {
    let mut data = raw.cipher.clone();
    aes256_cfb_decrypt(key, &raw.iv, &mut data);
    data.truncate(raw.data_len as usize);

    let computed = md5::compute(&data);
    if computed[..] != raw.md5_expected[..] {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "MD5 mismatch: decryption key is likely incorrect",
        ));
    }

    Ok(data)
}

/// Verify whether a candidate key can decrypt a raw encrypted block.
/// Returns `true` if the key produces a valid MD5 match.
pub fn verify_encrypted_block(raw: &RawEncryptedBlock, key: &[u8; 32]) -> bool {
    let mut data = raw.cipher.clone();
    aes256_cfb_decrypt(key, &raw.iv, &mut data);
    data.truncate(raw.data_len as usize);
    let computed = md5::compute(&data);
    computed[..] == raw.md5_expected[..]
}

fn read_encrypted_block(
    reader: &mut BufReader<&fs::File>,
    key: &[u8; 32],
) -> io::Result<EncryptedBlock> {
    let raw = read_raw_encrypted_block(reader)?;
    let data = decrypt_raw_block(&raw, key)?;
    Ok(EncryptedBlock { data })
}

// ----- Encrypted directory (pre-scan) ---------------------------------------

/// Raw information about an encrypted PCK directory.
/// Read once, then used to verify candidate keys without further I/O.
#[derive(Debug, Clone)]
pub struct EncryptedDirRaw {
    pub file_count: u32,
    pub block: RawEncryptedBlock,
}

/// Read the encrypted directory raw info from the PCK file.
/// Returns `None` if the directory is not encrypted.
pub fn read_dir_raw(
    reader: &mut BufReader<&fs::File>,
    dir_offset: u64,
    pack_flags: u32,
) -> io::Result<Option<EncryptedDirRaw>> {
    if pack_flags & PACK_DIR_ENCRYPTED == 0 {
        return Ok(None);
    }
    reader.seek(SeekFrom::Start(dir_offset))?;
    let file_count = read_u32_be(reader)?;
    let block = read_raw_encrypted_block(reader)?;
    Ok(Some(EncryptedDirRaw { file_count, block }))
}

// ----- Directory -----------------------------------------------------------

pub fn parse_directory(
    reader: &mut BufReader<&fs::File>,
    dir_offset: u64,
    pack_flags: u32,
    file_base: u64,
    key: &[u8; 32],
) -> io::Result<Vec<FileEntry>> {
    reader.seek(SeekFrom::Start(dir_offset))?;
    let file_count = read_u32_be(reader)?;

    if pack_flags & PACK_DIR_ENCRYPTED != 0 {
        let block = read_encrypted_block(reader, key)?;
        let mut cur = io::Cursor::new(&block.data);
        return Ok(parse_entries(&mut cur, file_count, file_base)?);
    }

    Ok(parse_entries(reader, file_count, file_base)?)
}

fn parse_entries<R: Read>(
    reader: &mut R,
    file_count: u32,
    file_base: u64,
) -> io::Result<Vec<FileEntry>> {
    let mut entries = Vec::with_capacity(file_count as usize);

    for _ in 0..file_count {
        let sl = reader_u32(reader)?;
        let pad = (4 - sl % 4) % 4;
        let actual_string_len = sl - pad;

        let mut name_buf = vec![0u8; actual_string_len as usize];
        reader.read_exact(&mut name_buf)?;

        let mut pad_buf = vec![0u8; pad as usize];
        reader.read_exact(&mut pad_buf)?;

        let path = String::from_utf8_lossy(&name_buf)
            .trim_end_matches('\0')
            .to_string();

        let ofs = reader_u64(reader)?;
        let size = reader_u64(reader)?;

        let mut md5 = [0u8; 16];
        reader.read_exact(&mut md5)?;

        let flags = reader_u32(reader)?;

        entries.push(FileEntry {
            path,
            offset: file_base + ofs,
            size,
            md5,
            encrypted: flags & PACK_FILE_ENCRYPTED != 0,
            removal: flags & PACK_FILE_REMOVAL != 0,
            delta: flags & PACK_FILE_DELTA != 0,
        });
    }

    Ok(entries)
}

// ----- File data reading ---------------------------------------------------

pub fn read_file_data(
    reader: &mut BufReader<&fs::File>,
    entry: &FileEntry,
    key: &[u8; 32],
) -> io::Result<Vec<u8>> {
    reader.seek(SeekFrom::Start(entry.offset))?;

    if entry.encrypted {
        let block = read_encrypted_block(reader, key)?;
        Ok(block.data)
    } else {
        let mut data = vec![0u8; entry.size as usize];
        reader.read_exact(&mut data)?;
        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_path(name: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "pck_tool_{}_{}_{}.bin",
            name,
            std::process::id(),
            stamp
        ))
    }

    fn write_temp(name: &str, data: &[u8]) -> PathBuf {
        let path = temp_path(name);
        fs::write(&path, data).unwrap();
        path
    }

    #[test]
    fn locate_standalone_pck() {
        let mut data = Vec::new();
        data.extend_from_slice(&PACK_HEADER_MAGIC.to_le_bytes());
        data.extend_from_slice(&[1, 2, 3, 4]);
        let path = write_temp("standalone", &data);

        let file = fs::File::open(&path).unwrap();
        let mut reader = BufReader::new(&file);
        let location = locate_pck(&mut reader).unwrap();

        assert_eq!(location.start, 0);
        assert_eq!(location.size, data.len() as u64);
        assert!(!location.embedded);

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn locate_embedded_pck() {
        let mut pck = Vec::new();
        pck.extend_from_slice(&PACK_HEADER_MAGIC.to_le_bytes());
        pck.extend_from_slice(&[9u8; 32]);

        let mut data = b"MZ fake exe".to_vec();
        let pck_start = data.len() as u64;
        data.extend_from_slice(&pck);
        data.extend_from_slice(&(pck.len() as u64).to_le_bytes());
        data.extend_from_slice(&PACK_HEADER_MAGIC.to_le_bytes());

        let path = write_temp("embedded", &data);
        let file = fs::File::open(&path).unwrap();
        let mut reader = BufReader::new(&file);

        let location = locate_pck(&mut reader).unwrap();
        assert_eq!(location.start, pck_start);
        assert_eq!(location.size, pck.len() as u64);
        assert!(location.embedded);
        assert_eq!(find_pck_header(&mut reader).unwrap(), pck_start as i64);

        fs::remove_file(path).unwrap();
    }
}

pub fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    }
}
