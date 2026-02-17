//! WSL2 backend for Windows.
//!
//! Instead of emulating CPU instructions via WHP (which has unfixable MSR bugs),
//! this backend manages a lightweight WSL2 Alpine Linux distro. Communication
//! between host and guest uses localhost TCP (WSL2 shares the host network namespace).

pub mod distro;
pub mod process;
pub mod rootfs;

use std::process::Child;
use std::net::TcpStream;
use std::time::{Duration, Instant};

use crate::backend::{HypervisorBackend, VmConfig};
use crate::error::{Error, Result};
use self::distro::{WslDistro, DEFAULT_DISTRO_NAME};

/// The TCP port the in-guest daemon listens on for control commands.
const DAEMON_CONTROL_PORT: u16 = 1025;

/// State of the WSL2 backend.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum WslState {
    /// Distro created/imported but daemon not running.
    Created,
    /// Daemon is running inside WSL.
    Running,
    /// Distro has been stopped.
    Stopped,
}

/// WSL2 backend that manages a lightweight Linux distro via WSL.
pub struct WslBackend {
    /// The managed WSL distro.
    distro: Option<WslDistro>,
    /// Current state.
    state: WslState,
    /// VM configuration.
    config: VmConfig,
    /// Handle to the background daemon process.
    daemon_process: Option<Child>,
}

/// Check if WSL2 is available on this system.
pub fn is_available() -> bool {
    process::check_wsl_available()
}

/// Full cleanup of the microvm WSL2 distro and its data.
///
/// Best-effort: terminates the distro, unregisters it (deletes the ext4.vhdx),
/// and removes the data directory (`%LOCALAPPDATA%\microvm-rs\`).
/// Individual errors are logged but do not prevent subsequent steps.
pub fn cleanup() {
    eprintln!("[WSL2] cleanup: terminating distro...");
    if let Ok(output) = process::run_wsl(&["--terminate", DEFAULT_DISTRO_NAME]) {
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            eprintln!("[WSL2] cleanup: terminate warning: {}", stderr.trim());
        }
    }

    eprintln!("[WSL2] cleanup: unregistering distro...");
    if let Ok(output) = process::run_wsl(&["--unregister", DEFAULT_DISTRO_NAME]) {
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            eprintln!("[WSL2] cleanup: unregister warning: {}", stderr.trim());
        }
    }

    eprintln!("[WSL2] cleanup: removing data directory...");
    if let Ok(dir) = rootfs::data_dir() {
        if dir.exists() {
            if let Err(e) = std::fs::remove_dir_all(&dir) {
                eprintln!("[WSL2] cleanup: remove_dir_all warning: {}", e);
            }
        }
    }

    eprintln!("[WSL2] cleanup: done");
}

/// Spawn a shell inside the microvm WSL distro with piped stdio.
///
/// Returns a `Child` whose stdin/stdout/stderr are piped, suitable for
/// programmatic use (e.g. wiring to xterm.js in Velocitty).
///
/// The distro must already exist (i.e. `cargo run -- run` must have been
/// executed at least once to import it).
pub fn spawn_shell() -> Result<std::process::Child> {
    if !distro::WslDistro::exists(DEFAULT_DISTRO_NAME)? {
        return Err(Error::WslError(
            "microvm-rs distro not found. Run 'microvm run' first to create it.".into(),
        ));
    }
    // Use -i to force interactive mode (prompt + command reading) even with
    // piped stdio.  Without -i the shell sees no TTY and stays silent.
    // Note: there is no character echo (no PTY), but commands work.
    process::spawn_wsl_interactive(&[
        "-d", DEFAULT_DISTRO_NAME, "--cd", "/root", "--", "/bin/sh", "-i",
    ])
}

/// Open an interactive shell inside the microvm WSL distro.
///
/// Inherits stdin/stdout/stderr from the calling process, giving the user
/// a direct terminal session. Blocks until the user exits the shell.
pub fn run_shell_interactive() -> Result<()> {
    if !distro::WslDistro::exists(DEFAULT_DISTRO_NAME)? {
        return Err(Error::WslError(
            "microvm-rs distro not found. Run 'microvm run' first to create it.".into(),
        ));
    }
    let mut child = process::spawn_wsl_inherited(&[
        "-d", DEFAULT_DISTRO_NAME, "--cd", "/root", "--", "/bin/sh", "-l",
    ])?;
    let status = child.wait().map_err(|e| Error::WslError(format!("Shell process error: {}", e)))?;
    if !status.success() {
        if let Some(code) = status.code() {
            return Err(Error::WslError(format!("Shell exited with code {}", code)));
        }
    }
    Ok(())
}

impl WslBackend {
    /// Create a new WSL2 backend with the given configuration.
    pub fn new(config: VmConfig) -> Result<Self> {
        Ok(Self {
            distro: None,
            state: WslState::Created,
            config,
            daemon_process: None,
        })
    }

    /// Take the daemon process's stdout handle.
    ///
    /// Returns `None` if the daemon isn't running or stdout was already taken.
    pub fn take_daemon_stdout(&mut self) -> Option<std::process::ChildStdout> {
        self.daemon_process.as_mut().and_then(|child| child.stdout.take())
    }

    /// Ensure the WSL distro is imported and ready.
    fn ensure_distro(&mut self) -> Result<()> {
        if self.distro.is_some() {
            return Ok(());
        }

        let install_path = rootfs::wsl_install_path()?;
        let rootfs_path = rootfs::extract_rootfs(self.config.rootfs.as_ref())?;

        let needs_setup = !WslDistro::exists(DEFAULT_DISTRO_NAME)?;
        let distro = WslDistro::ensure_exists(DEFAULT_DISTRO_NAME, &install_path, &rootfs_path)?;

        if needs_setup {
            eprintln!("[WSL2] First run — provisioning distro...");
            self.provision_distro(&distro)?;
        }

        self.distro = Some(distro);
        Ok(())
    }

    /// Provision a freshly-imported distro with packages and scripts.
    fn provision_distro(&self, distro: &WslDistro) -> Result<()> {
        // Configure WSL to not mount Windows drives — keeps the VM isolated
        eprintln!("[WSL2] Configuring wsl.conf for isolation...");
        let wsl_conf = b"[automount]\nenabled = false\n\n[interop]\nappendWindowsPath = false\n";
        let output = distro.exec_with_stdin("tee", &["/etc/wsl.conf"], wsl_conf)?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            eprintln!("[WSL2] Warning: failed to write wsl.conf: {}", stderr);
        }

        // Install socat (needed for the control daemon)
        eprintln!("[WSL2] Installing packages...");
        let output = distro.exec("sh", &["-c", "apk update && apk add --no-cache socat"])?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            eprintln!("[WSL2] Warning: package install failed: {}", stderr);
            // Continue anyway — the fallback nc listener may work
        }

        // Write the init script into the distro via stdin (avoids shell escaping issues)
        eprintln!("[WSL2] Installing init script...");
        let init_script = include_str!("../../../guest/wsl-rootfs/init-microvm.sh");

        // Create directory first
        let output = distro.exec("sh", &["-c", "mkdir -p /etc/microvm"])?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::WslError(format!("Failed to create /etc/microvm: {}", stderr)));
        }

        // Pipe the script content via stdin to tee
        let output = distro.exec_with_stdin(
            "tee", &["/etc/microvm/init-microvm.sh"],
            init_script.as_bytes(),
        )?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::WslError(format!("Failed to install init script: {}", stderr)));
        }

        // Make it executable
        let output = distro.exec("chmod", &["+x", "/etc/microvm/init-microvm.sh"])?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::WslError(format!("Failed to chmod init script: {}", stderr)));
        }

        eprintln!("[WSL2] Provisioning complete.");
        Ok(())
    }

    /// Wait for the daemon to become reachable on localhost.
    fn wait_for_daemon(&self, timeout: Duration) -> Result<()> {
        let start = Instant::now();
        let addr = format!("127.0.0.1:{}", DAEMON_CONTROL_PORT);

        while start.elapsed() < timeout {
            match TcpStream::connect_timeout(
                &addr.parse().unwrap(),
                Duration::from_millis(500),
            ) {
                Ok(_stream) => return Ok(()),
                Err(_) => {
                    std::thread::sleep(Duration::from_millis(200));
                }
            }
        }

        Err(Error::WslError(format!(
            "Daemon did not become reachable on {} within {:?}",
            addr, timeout
        )))
    }

    /// Send a control command to the daemon via TCP.
    fn send_command(&self, cmd: &str) -> Result<String> {
        use std::io::{Read, Write};

        let addr = format!("127.0.0.1:{}", DAEMON_CONTROL_PORT);
        let mut stream = TcpStream::connect_timeout(
            &addr.parse().unwrap(),
            Duration::from_secs(5),
        ).map_err(|e| Error::WslError(format!("Failed to connect to daemon: {}", e)))?;

        stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
        stream.set_write_timeout(Some(Duration::from_secs(5))).ok();

        stream.write_all(cmd.as_bytes())
            .map_err(|e| Error::WslError(format!("Failed to send command: {}", e)))?;
        stream.write_all(b"\n")
            .map_err(|e| Error::WslError(format!("Failed to send newline: {}", e)))?;
        stream.flush()
            .map_err(|e| Error::WslError(format!("Failed to flush: {}", e)))?;

        let mut response = String::new();
        stream.read_to_string(&mut response)
            .map_err(|e| Error::WslError(format!("Failed to read response: {}", e)))?;

        Ok(response)
    }
}

impl HypervisorBackend for WslBackend {
    fn start(&mut self) -> Result<()> {
        if self.state == WslState::Running {
            return Err(Error::AlreadyRunning);
        }

        // Ensure distro is imported
        self.ensure_distro()?;
        let distro = self.distro.as_ref().unwrap();

        // Launch the daemon inside WSL
        let child = distro.exec_background("/bin/sh", &["/etc/microvm/init-microvm.sh"])?;
        self.daemon_process = Some(child);

        // Wait for daemon to become reachable
        self.wait_for_daemon(Duration::from_secs(30))?;

        self.state = WslState::Running;
        Ok(())
    }

    fn pause(&mut self) -> Result<()> {
        if self.state != WslState::Running {
            return Err(Error::NotRunning);
        }
        self.send_command("pause")?;
        Ok(())
    }

    fn resume(&mut self) -> Result<()> {
        if self.state != WslState::Running {
            return Err(Error::NotRunning);
        }
        self.send_command("resume")?;
        Ok(())
    }

    fn shutdown(&mut self) -> Result<()> {
        if self.state != WslState::Running {
            return Err(Error::NotRunning);
        }

        // Send shutdown command to daemon
        let _ = self.send_command("shutdown");

        // Terminate the WSL distro
        if let Some(distro) = &self.distro {
            let _ = distro.terminate();
        }

        // Clean up daemon process
        if let Some(mut child) = self.daemon_process.take() {
            let _ = child.kill();
            let _ = child.wait();
        }

        self.state = WslState::Stopped;
        Ok(())
    }

    fn kill(&mut self) -> Result<()> {
        // Force terminate the WSL distro immediately
        if let Some(distro) = &self.distro {
            let _ = distro.terminate();
        }

        // Kill daemon process
        if let Some(mut child) = self.daemon_process.take() {
            let _ = child.kill();
            let _ = child.wait();
        }

        self.state = WslState::Stopped;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "wsl2"
    }
}

impl Drop for WslBackend {
    fn drop(&mut self) {
        // Ensure cleanup on drop
        if self.state == WslState::Running {
            let _ = self.kill();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wsl_backend_name() {
        let config = VmConfig {
            memory_mb: 512,
            vcpus: 1,
            kernel: None,
            initrd: None,
            rootfs: None,
            cmdline: String::new(),
        };
        let backend = WslBackend::new(config).unwrap();
        assert_eq!(backend.name(), "wsl2");
    }

    #[test]
    fn test_wsl_state_initial() {
        let config = VmConfig {
            memory_mb: 512,
            vcpus: 1,
            kernel: None,
            initrd: None,
            rootfs: None,
            cmdline: String::new(),
        };
        let backend = WslBackend::new(config).unwrap();
        assert_eq!(backend.state, WslState::Created);
    }
}
