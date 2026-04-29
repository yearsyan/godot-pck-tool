# pck-tool

Godot `.pck` file parser, inspector, and extractor written in Rust.

Supports both plain and encrypted PCK archives (AES-256-CFB), including the embedded PCK trailer found in self-contained executables.

## Install

Download a prebuilt binary from [Releases](https://github.com/yearsyan/godot-pck-tool/releases), or build from source:

```bash
cargo install --git https://github.com/yearsyan/godot-pck-tool
```

## Usage

```bash
# List all files
pck-tool --file game.pck list

# List only encrypted files
pck-tool --file game.pck list --encrypted

# Extract all files (preserving directory structure)
pck-tool --file game.pck extract --output ./out

# Extract flat (no subdirectories)
pck-tool --file game.pck extract --output ./out --flat

# Output a single file to stdout (for piping)
pck-tool --file game.pck pipe icon.svg > icon.svg

# Decrypt with a key (64 hex chars = 32 bytes)
pck-tool --file game.pck --key <64hex> list
pck-tool --file game.pck --key <64hex> extract --output ./out
pck-tool --file game.pck --key <64hex> pipe icon.svg
```

## PCK Format

| Field | Size | Description |
|-------|------|-------------|
| Magic | 4B | `GDPC` (0x43504447) |
| Version | 4B | Format version (3) |
| Godot ver | 12B | Major, minor, patch |
| Flags | 4B | enc_dir, rel_filebase, sparse_bundle |
| File base | 8B | Offset where file data starts |
| Dir offset | 8B | Offset to the file directory |
| Reserved | 64B | Padding to 100 bytes, then align to 16 |

The directory follows at `dir_offset`, containing a file count followed by per-file records (path, offset, size, MD5, flags). Encryption uses AES-256-CFB with a per-entry IV and MD5 integrity check.

