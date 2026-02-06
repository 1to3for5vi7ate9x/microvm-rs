//! Low-level wsl.exe CLI wrapper.
//!
//! Provides helper functions for interacting with WSL via the wsl.exe command.

use std::process::{Command, Output, Child, Stdio};

use crate::error::{Error, Result};

/// Check if WSL2 is available on this system.
pub fn check_wsl_available() -> bool {
    run_wsl(&["--status"])
        .map(|output| output.status.success())
        .unwrap_or(false)
}

/// List all registered WSL distributions.
pub fn list_distros() -> Result<Vec<String>> {
    let output = run_wsl(&["--list", "--quiet"])?;
    if !output.status.success() {
        return Err(Error::WslError("Failed to list WSL distributions".into()));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let distros: Vec<String> = stdout
        .lines()
        .map(|line| line.trim().trim_matches('\0').to_string())
        .filter(|s| !s.is_empty())
        .collect();

    Ok(distros)
}

/// Run wsl.exe with the given arguments and wait for completion.
pub fn run_wsl(args: &[&str]) -> Result<Output> {
    Command::new("wsl.exe")
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| Error::WslError(format!("Failed to run wsl.exe: {}", e)))
}

/// Spawn wsl.exe with the given arguments as a background process.
pub fn run_wsl_background(args: &[&str]) -> Result<Child> {
    Command::new("wsl.exe")
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| Error::WslError(format!("Failed to spawn wsl.exe: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_wsl_available() {
        // This test just verifies the function doesn't panic.
        // Whether WSL is actually available depends on the system.
        let _available = check_wsl_available();
    }
}
