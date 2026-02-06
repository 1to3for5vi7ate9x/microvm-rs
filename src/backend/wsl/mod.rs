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

    /// Ensure the WSL distro is imported and ready.
    fn ensure_distro(&mut self) -> Result<()> {
        if self.distro.is_some() {
            return Ok(());
        }

        let install_path = rootfs::wsl_install_path()?;
        let rootfs_path = rootfs::extract_rootfs(self.config.rootfs.as_ref())?;

        let distro = WslDistro::ensure_exists(DEFAULT_DISTRO_NAME, &install_path, &rootfs_path)?;
        self.distro = Some(distro);
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
