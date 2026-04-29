use std::env;
use std::fs;
use std::io::{self, Read};
use std::process::Command;

use flate2::read::GzDecoder;
use serde::Deserialize;

const GITHUB_API: &str = "https://api.github.com/repos/yearsyan/godot-pck-tool/releases/latest";

#[derive(Deserialize)]
struct ReleaseAsset {
    name: String,
    browser_download_url: String,
}

#[derive(Deserialize)]
struct Release {
    tag_name: String,
    assets: Vec<ReleaseAsset>,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct SemVer {
    major: u32,
    minor: u32,
    patch: u32,
}

fn parse_semver(v: &str) -> Option<SemVer> {
    let v = v.strip_prefix('v').unwrap_or(v);
    let mut parts = v.splitn(3, '.');
    Some(SemVer {
        major: parts.next()?.parse().ok()?,
        minor: parts.next()?.parse().ok()?,
        patch: parts.next().unwrap_or("0").parse().ok()?,
    })
}

fn target_triple() -> &'static str {
    if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
        "x86_64-apple-darwin"
    } else if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        "aarch64-apple-darwin"
    } else if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        "x86_64-unknown-linux-musl"
    } else if cfg!(all(target_os = "linux", target_arch = "aarch64")) {
        "aarch64-unknown-linux-musl"
    } else if cfg!(all(target_os = "windows", target_arch = "x86_64")) {
        "x86_64-pc-windows-msvc"
    } else if cfg!(all(target_os = "windows", target_arch = "aarch64")) {
        "aarch64-pc-windows-msvc"
    } else {
        "unknown"
    }
}

pub fn upgrade() -> io::Result<()> {
    let exe_path = env::current_exe()?;
    let pkg_version = env!("CARGO_PKG_VERSION");
    let current_version = parse_semver(pkg_version)
        .expect("CARGO_PKG_VERSION must be valid semver");
    let target = target_triple();

    // Clean up stale tmp from previous failed upgrade
    let _ = fs::remove_file(exe_path.with_extension("tmp"));

    eprintln!("Current version: {}  ({})", pkg_version, target);
    eprintln!("Fetching latest release from GitHub...");

    let response = ureq::get(GITHUB_API)
        .set("User-Agent", "pck-tool-upgrade")
        .call()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    let release: Release = response
        .into_json()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let latest_version = parse_semver(&release.tag_name).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Invalid tag name: {}", release.tag_name),
        )
    })?;

    if latest_version <= current_version {
        eprintln!(
            "Already up to date (latest is {}, current is v{})",
            release.tag_name, pkg_version
        );
        return Ok(());
    }

    eprintln!(
        "New version available: v{} → {}",
        pkg_version, release.tag_name
    );

    let asset_name = format!("pck-tool-{}.tar.gz", target);
    let asset = release
        .assets
        .iter()
        .find(|a| a.name == asset_name)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "No asset '{}' found in {}. Available: {}",
                    asset_name,
                    release.tag_name,
                    release
                        .assets
                        .iter()
                        .map(|a| a.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            )
        })?;

    eprintln!("Downloading {} ...", asset.browser_download_url);

    let resp = ureq::get(&asset.browser_download_url)
        .set("User-Agent", "pck-tool-upgrade")
        .call()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    let mut body = Vec::new();
    resp.into_reader()
        .read_to_end(&mut body)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    let mut decoder = GzDecoder::new(&body[..]);
    let mut binary = Vec::new();
    decoder
        .read_to_end(&mut binary)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let tmp_path = exe_path.with_extension("tmp");
    fs::write(&tmp_path, &binary)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&tmp_path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&tmp_path, perms)?;
    }

    // Spawn the tmp binary to replace us, then exit immediately.
    // The tmp process copies itself over the original path and exits.
    let exe_str = exe_path.to_string_lossy().to_string();

    let mut cmd = Command::new(&tmp_path);
    cmd.arg("install").arg(&exe_str);

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x00000008;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        cmd.creation_flags(DETACHED_PROCESS | CREATE_NO_WINDOW);
    }

    cmd.spawn().map_err(|e| {
        let _ = fs::remove_file(&tmp_path);
        io::Error::new(io::ErrorKind::Other, format!("Failed to launch installer: {}", e))
    })?;

    eprintln!(
        "Installing {} ... (process will exit now, tmp installer takes over)",
        release.tag_name
    );

    std::process::exit(0);
}
