# AGENTS.md

## Project

`pck-tool` — Rust CLI for inspecting, extracting, and decrypting Godot `.pck` archives (AES-256-CFB).

## Directory structure

```
src/
  main.rs          # All logic in single binary crate
.github/workflows/
  release.yml      # Tag-triggered multi-platform build + GitHub Release
```

## Build & Test

```bash
cargo build --release
cargo test         # currently no tests; add when possible
```

For local validation, use a real .pck file:

```bash
cargo run --release -- --file path/to/game.pck list
cargo run --release -- --file path/to/game.pck extract --output /tmp/out
cargo run --release -- --file path/to/game.pck pipe icon.svg
```

## PCK format (from Godot source analysis)

### Godot source files referenced
- `core/io/file_access_pack.h`  — magic, flags, structs
- `core/io/file_access_pack.cpp` — `try_open_pack()` reading logic
- `core/io/file_access_encrypted.cpp` — `open_and_parse()` decryption
- `core/crypto/crypto_core.h` — AESContext CFB API
- `editor/export/editor_export_platform.cpp` — `_store_header()`, `_encrypt_and_store_directory()`
- `core/io/pck_packer.cpp` — runtime PCK creation (PCKPacker class)

### Header (100 bytes before alignment padding)

| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 | Magic: `GDPC` (0x43504447 LE) |
| 4 | 4 | Version: 3 |
| 8 | 4 | Godot major |
| 12 | 4 | Godot minor |
| 16 | 4 | Godot patch |
| 20 | 4 | PackFlags: `PACK_DIR_ENCRYPTED(1)`, `PACK_REL_FILEBASE(2)`, `PACK_SPARSE_BUNDLE(4)` |
| 24 | 8 | File base offset (relative to start; V3 adds pack_start_pos) |
| 32 | 8 | Directory offset (relative) |
| 40 | 64 | Reserved (16 × u32 = 0) |

Then alignment padding to next 16-byte boundary (`PCK_PADDING = 16`).

### Directory entry (at `dir_offset`)

```
file_count: u32
For each file:
  string_len + pad: u32  (pad = (4 - string_len % 4) % 4, so total is multiple of 4)
  path: [u8; string_len]
  pad: [u8; pad]          (zeros)
  offset: u64             (relative to file_base)
  size: u64               (original data size)
  md5: [u8; 16]           (of original data, used for integrity check on encrypted files)
  flags: u32              (PACK_FILE_ENCRYPTED=1, PACK_FILE_REMOVAL=2, PACK_FILE_DELTA=4)
```

### Encryption (AES-256-CFB)

- Key: 32 bytes (user provides 64-char hex string)
- Both directory encryption and per-file encryption use the same key
- Encrypted block layout (when `use_magic=false`, as used in PCK):
  - MD5 of plaintext: 16 bytes
  - Data length: u64
  - IV: 16 bytes (random per block)
  - Ciphertext: padded to 16-byte boundary
- CFB mode: encrypt IV → XOR with input → feedback ciphertext as next IV
  - **Both encrypt and decrypt use AES encrypt operation** (CFB property)
- MD5 is verified after decryption to detect wrong keys or corruption

### Embedded PCK (self-contained executable)

Some .pck are appended to the executable. The trailer at end of file is:
```
PCK data ... | u64 pck_size | u32 "GDPC"
```
The tool detects this by first reading offset 0, then checking the trailer.

## CLI design

Single binary with clap derive:
- `list` — prints file table to stdout, metadata to stderr
- `extract` — writes files to disk, preserves directory structure from pck paths
- `pipe` — writes single file content to stdout (no extra output), usable with `|` or `>`

## CI / CD

`.github/workflows/release.yml`:
- Trigger: push `v*` tag
- 3 parallel build jobs: macos-latest, windows-latest, ubuntu-latest (musl)
- Linux uses `x86_64-unknown-linux-musl` for static binary
- Release step uses `softprops/action-gh-release@v2` with `generate_release_notes: true`

## Key insights

1. **CFB decryption = CFB encryption**: In CFB mode, decryption uses the AES *encrypt* operation internally. So `aes256_cfb_decrypt` and `aes256_cfb_encrypt` are the same function.
2. **String padding**: Directory path strings are padded to 4-byte alignment with null bytes. The stored length field is `string_len + pad`. Trailing nulls must be stripped for clean display.
3. **V3 file_base/dir_offset**: Both are relative to the start of the PCK header (magic position), not absolute file offsets.
4. **No "GDEC" magic in PCK**: When `use_magic=false`, encrypted data starts directly with MD5 hash — no 4-byte magic prefix.
5. **PCK dir may be plain**: Directory encryption (`PACK_DIR_ENCRYPTED`) and file encryption (`PACK_FILE_ENCRYPTED`) are independent. Many PCKs encrypt only files, not the directory.
