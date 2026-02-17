//! WSL2 distro lifecycle management.
//!
//! Handles importing, querying, executing commands in, and unregistering
//! WSL2 distributions used by microvm.

use std::path::PathBuf;
use std::process::{Child, Output};

use crate::error::{Error, Result};
use super::process;

/// Default distro name used by microvm.
pub const DEFAULT_DISTRO_NAME: &str = "microvm-rs";

/// Manages a WSL2 distribution instance.
pub struct WslDistro {
    /// Distribution name (as registered with WSL).
    name: String,
    /// Path where the distro is installed on the host filesystem.
    install_path: PathBuf,
}

impl WslDistro {
    /// Check if a distribution with the given name exists.
    pub fn exists(name: &str) -> Result<bool> {
        let distros = process::list_distros()?;
        Ok(distros.iter().any(|d| d == name))
    }

    /// Import a new distribution from a rootfs tarball.
    ///
    /// - `name`: Distribution name to register.
    /// - `install_path`: Directory where WSL stores the distro's virtual disk.
    /// - `rootfs_path`: Path to the rootfs tarball (.tar.gz).
    pub fn import(name: &str, install_path: &PathBuf, rootfs_path: &PathBuf) -> Result<Self> {
        let install_str = install_path.to_string_lossy();
        let rootfs_str = rootfs_path.to_string_lossy();

        // Create install directory if it doesn't exist
        std::fs::create_dir_all(install_path)
            .map_err(|e| Error::WslError(format!("Failed to create install directory: {}", e)))?;

        let output = process::run_wsl(&[
            "--import",
            name,
            &install_str,
            &rootfs_str,
            "--version", "2",
        ])?;

        if !output.status.success() {
            let stderr = process::decode_wsl_output(&output.stderr);
            let stdout = process::decode_wsl_output(&output.stdout);
            let msg = if stderr.trim().is_empty() { stdout } else { stderr };
            return Err(Error::WslError(format!("Failed to import distro '{}': {}", name, msg.trim())));
        }

        Ok(Self {
            name: name.to_string(),
            install_path: install_path.clone(),
        })
    }

    /// Ensure a distribution exists, importing it if necessary.
    ///
    /// - `name`: Distribution name.
    /// - `install_path`: Directory for the distro's virtual disk.
    /// - `rootfs_path`: Path to rootfs tarball (used only if import is needed).
    pub fn ensure_exists(name: &str, install_path: &PathBuf, rootfs_path: &PathBuf) -> Result<Self> {
        if Self::exists(name)? {
            Ok(Self {
                name: name.to_string(),
                install_path: install_path.clone(),
            })
        } else {
            Self::import(name, install_path, rootfs_path)
        }
    }

    /// Execute a command inside the distribution and wait for it to complete.
    pub fn exec(&self, cmd: &str, args: &[&str]) -> Result<Output> {
        let mut wsl_args = vec!["-d", &self.name, "--", cmd];
        wsl_args.extend_from_slice(args);
        process::run_wsl(&wsl_args)
    }

    /// Execute a command inside the distribution, piping data to its stdin.
    pub fn exec_with_stdin(&self, cmd: &str, args: &[&str], stdin_data: &[u8]) -> Result<Output> {
        let mut wsl_args = vec!["-d", &self.name, "--", cmd];
        wsl_args.extend_from_slice(args);
        process::run_wsl_with_stdin(&wsl_args, stdin_data)
    }

    /// Execute a command inside the distribution as a background process.
    pub fn exec_background(&self, cmd: &str, args: &[&str]) -> Result<Child> {
        let mut wsl_args = vec!["-d", &self.name, "--", cmd];
        wsl_args.extend_from_slice(args);
        process::run_wsl_background(&wsl_args)
    }

    /// Terminate the running distribution.
    pub fn terminate(&self) -> Result<()> {
        let output = process::run_wsl(&["--terminate", &self.name])?;
        if !output.status.success() {
            let stderr = process::decode_wsl_output(&output.stderr);
            return Err(Error::WslError(format!("Failed to terminate distro '{}': {}", self.name, stderr)));
        }
        Ok(())
    }

    /// Unregister (delete) the distribution.
    pub fn unregister(&self) -> Result<()> {
        let output = process::run_wsl(&["--unregister", &self.name])?;
        if !output.status.success() {
            let stderr = process::decode_wsl_output(&output.stderr);
            return Err(Error::WslError(format!("Failed to unregister distro '{}': {}", self.name, stderr)));
        }
        Ok(())
    }

    /// Get the distribution name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the install path.
    pub fn install_path(&self) -> &PathBuf {
        &self.install_path
    }

    /// Spawn an interactive shell inside the distro with piped stdio.
    ///
    /// Returns a `Child` whose stdin/stdout/stderr can be wired to a terminal
    /// emulator (e.g. xterm.js in Velocitty).
    pub fn spawn_shell(&self) -> Result<Child> {
        process::spawn_wsl_interactive(&[
            "-d", &self.name, "--cd", "/root", "--", "/bin/sh", "-i",
        ])
    }

    /// Spawn an interactive shell with inherited stdio (for direct CLI use).
    ///
    /// Blocks the calling thread until the shell process exits.
    pub fn spawn_shell_inherited(&self) -> Result<Child> {
        process::spawn_wsl_inherited(&["-d", &self.name, "--cd", "/root", "--", "/bin/sh", "-l"])
    }
}
