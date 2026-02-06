//! Embedded rootfs management for the WSL2 backend.
//!
//! On Windows, we embed a minimal Alpine Linux rootfs (~3MB) at compile time.
//! This tarball is extracted to `%LOCALAPPDATA%\microvm-rs\` at runtime and
//! imported into WSL2.

use std::path::PathBuf;

use crate::error::{Error, Result};

/// Alpine minirootfs embedded at compile time.
/// This file must exist at build time. If it doesn't, the build will fail.
/// Download from: https://dl-cdn.alpinelinux.org/alpine/latest-stable/releases/x86_64/
#[cfg(target_os = "windows")]
const ALPINE_ROOTFS: &[u8] = include_bytes!("../../../guest/wsl-rootfs/alpine-minirootfs.tar.gz");

/// Get the base directory for microvm data on the host.
///
/// Returns `%LOCALAPPDATA%\microvm-rs\` (e.g., `C:\Users\<user>\AppData\Local\microvm-rs\`).
pub fn data_dir() -> Result<PathBuf> {
    let local_app_data = std::env::var("LOCALAPPDATA")
        .map_err(|_| Error::WslError("LOCALAPPDATA environment variable not set".into()))?;
    Ok(PathBuf::from(local_app_data).join("microvm-rs"))
}

/// Get the path where the WSL distro virtual disk will be stored.
pub fn wsl_install_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("wsl"))
}

/// Extract the embedded rootfs tarball to disk if not already present.
///
/// Returns the path to the extracted tarball.
/// If `override_path` is provided, returns that path instead (for custom rootfs).
pub fn extract_rootfs(override_path: Option<&PathBuf>) -> Result<PathBuf> {
    if let Some(path) = override_path {
        if path.exists() {
            return Ok(path.clone());
        }
        return Err(Error::WslError(format!("Custom rootfs not found: {}", path.display())));
    }

    let dir = data_dir()?;
    let rootfs_path = dir.join("alpine-rootfs.tar.gz");

    // If already extracted and file has correct size, skip
    if rootfs_path.exists() {
        if let Ok(meta) = std::fs::metadata(&rootfs_path) {
            if meta.len() == ALPINE_ROOTFS.len() as u64 {
                return Ok(rootfs_path);
            }
        }
    }

    // Create directory and write the tarball
    std::fs::create_dir_all(&dir)
        .map_err(|e| Error::WslError(format!("Failed to create data directory: {}", e)))?;

    std::fs::write(&rootfs_path, ALPINE_ROOTFS)
        .map_err(|e| Error::WslError(format!("Failed to write rootfs tarball: {}", e)))?;

    Ok(rootfs_path)
}
