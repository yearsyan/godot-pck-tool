# pck-tool

Godot `.pck` file parser, inspector, and extractor written in Rust.

Supports both plain and encrypted PCK archives (AES-256-CFB), including the embedded PCK trailer found in self-contained executables.

Also supports **CTEX texture reconstruction** — converting Godot's compressed `.ctex` textures back to `.png` during extraction (see `--untex` below).

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

# Extract with CTEX texture reconstruction (.ctex → .png)
pck-tool --file game.pck extract --output ./out --untex

# Extract flat (no subdirectories)
pck-tool --file game.pck extract --output ./out --flat

# Output a single file to stdout (for piping)
pck-tool --file game.pck pipe icon.svg > icon.svg

# Extract an embedded PCK from a self-contained executable
pck-tool --file Game.exe extract-pck --output Game.pck

# Decrypt with a key (64 hex chars = 32 bytes)
pck-tool --file game.pck --key <64hex> list
pck-tool --file game.pck --key <64hex> extract --output ./out
pck-tool --file game.pck --key <64hex> pipe icon.svg
```

If `--output` is omitted, `extract-pck` writes next to the input using the same
base name and a `.pck` extension.

### CTEX Texture Reconstruction (`--untex` / `-u`)

When `--untex` is passed to `extract`, the tool reads `.import` files in the
output directory, locates the corresponding `.ctex` (CompressedTexture2D)
files, and converts them back to `.png` at the original source path.

| CTEX DataFormat | Supported | Notes |
|-----------------|-----------|-------|
| WEBP (2) | Yes | WebP blob decoded to PNG via the `image` crate |
| PNG (1) | Yes | PNG blob copied directly |
| RAW (0) | No | GPU-compressed format (BC7/BC3/etc.), needs GPU decompression |
| BASIS (3) | No | Basis Universal KTX2, needs `basisu_transcoder` |

Original `.import` and `.ctex` files are preserved.

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

