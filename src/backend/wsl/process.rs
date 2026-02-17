//! Low-level wsl.exe CLI wrapper.
//!
//! Provides helper functions for interacting with WSL via the wsl.exe command.

use std::process::{Command, Output, Child, Stdio};

use crate::error::{Error, Result};

/// Decode bytes that may be UTF-16LE (common from wsl.exe management commands)
/// or plain UTF-8. Returns a UTF-8 String.
pub fn decode_wsl_output(bytes: &[u8]) -> String {
    // Try UTF-16LE first: if the bytes have even length and contain interleaved
    // null bytes (typical for ASCII text in UTF-16LE), decode as UTF-16LE.
    if bytes.len() >= 2 && bytes.len() % 2 == 0 {
        // Check if this looks like UTF-16LE (every other byte is 0 for ASCII)
        let looks_like_utf16 = bytes.len() >= 4
            && bytes.iter().skip(1).step_by(2).take(4).all(|&b| b == 0);
        if looks_like_utf16 {
            let u16s: Vec<u16> = bytes
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect();
            // Skip BOM if present
            let start = if u16s.first() == Some(&0xFEFF) { 1 } else { 0 };
            return String::from_utf16_lossy(&u16s[start..]);
        }
    }
    // Fall back to UTF-8
    String::from_utf8_lossy(bytes).into_owned()
}

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

    let stdout = decode_wsl_output(&output.stdout);
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

/// Run wsl.exe with the given arguments, piping data to stdin.
pub fn run_wsl_with_stdin(args: &[&str], stdin_data: &[u8]) -> Result<Output> {
    use std::io::Write;

    let mut child = Command::new("wsl.exe")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| Error::WslError(format!("Failed to spawn wsl.exe: {}", e)))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(stdin_data)
            .map_err(|e| Error::WslError(format!("Failed to write to wsl stdin: {}", e)))?;
    }

    child.wait_with_output()
        .map_err(|e| Error::WslError(format!("Failed to wait for wsl.exe: {}", e)))
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

/// Spawn wsl.exe with piped stdio (for programmatic use / Velocitty).
pub fn spawn_wsl_interactive(args: &[&str]) -> Result<Child> {
    Command::new("wsl.exe")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| Error::WslError(format!("Failed to spawn wsl.exe: {}", e)))
}

/// Spawn wsl.exe with inherited stdio (for interactive CLI use).
pub fn spawn_wsl_inherited(args: &[&str]) -> Result<Child> {
    Command::new("wsl.exe")
        .args(args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
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
