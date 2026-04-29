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
    // Standalone PCK: start of file
    reader.seek(SeekFrom::Start(0))?;
    let magic = read_u32_be(reader)?;
    if magic == PACK_HEADER_MAGIC {
        return Ok(0);
    }

    // Embedded trailer: [pck_size: u64 | GDPC: u32] at end of file
    let file_len = reader.seek(SeekFrom::End(0))?;
    if file_len >= 12 {
        reader.seek(SeekFrom::End(-4))?;
        let magic = read_u32_be(reader)?;
        if magic == PACK_HEADER_MAGIC {
            reader.seek(SeekFrom::End(-12))?;
            let pck_size = read_u64_be(reader)?;
            if pck_size + 12 <= file_len {
                reader.seek(SeekFrom::End(-((pck_size + 12) as i64)))?;
                let magic = read_u32_be(reader)?;
                if magic == PACK_HEADER_MAGIC {
                    return Ok(reader.stream_position()? as i64 - 4);
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

fn read_encrypted_block(
    reader: &mut BufReader<&fs::File>,
    key: &[u8; 32],
) -> io::Result<EncryptedBlock> {
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

    aes256_cfb_decrypt(key, &iv, &mut cipher);
    cipher.truncate(data_len as usize);

    let computed = md5::compute(&cipher);
    if computed[..] != md5_expected[..] {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "MD5 mismatch: decryption key is likely incorrect",
        ));
    }

    Ok(EncryptedBlock { data: cipher })
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

pub fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    }
}
