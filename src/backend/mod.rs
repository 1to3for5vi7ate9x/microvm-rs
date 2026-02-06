//! Hypervisor backend abstraction.
//!
//! This module defines the trait that all platform-specific backends must implement,
//! and provides the logic to select and create the appropriate backend.

use std::path::PathBuf;

use crate::error::Result;

// Platform-specific backend modules
#[cfg(target_os = "macos")]
pub mod hvf;

#[cfg(target_os = "windows")]
pub mod wsl;

#[cfg(target_os = "linux")]
pub mod kvm;

/// Configuration for creating a VM.
#[derive(Debug, Clone)]
pub struct VmConfig {
    /// Memory size in megabytes.
    pub memory_mb: u32,
    /// Number of vCPUs.
    pub vcpus: u32,
    /// Path to kernel image.
    pub kernel: Option<PathBuf>,
    /// Path to initrd.
    pub initrd: Option<PathBuf>,
    /// Path to root filesystem.
    pub rootfs: Option<PathBuf>,
    /// Kernel command line.
    pub cmdline: String,
}

/// Trait that all hypervisor backends must implement.
///
/// This provides a platform-agnostic interface for VM operations.
pub trait HypervisorBackend: Send {
    /// Start the VM (begin executing vCPUs).
    fn start(&mut self) -> Result<()>;

    /// Pause all vCPUs.
    fn pause(&mut self) -> Result<()>;

    /// Resume paused vCPUs.
    fn resume(&mut self) -> Result<()>;

    /// Request graceful shutdown (e.g., ACPI power button).
    fn shutdown(&mut self) -> Result<()>;

    /// Force kill the VM immediately.
    fn kill(&mut self) -> Result<()>;

    /// Get the backend name (e.g., "hvf", "wsl2", "kvm").
    fn name(&self) -> &'static str;
}

/// Check if the hypervisor is available on this platform.
pub fn is_available() -> bool {
    #[cfg(target_os = "macos")]
    {
        hvf::is_available()
    }

    #[cfg(target_os = "windows")]
    {
        wsl::is_available()
    }

    #[cfg(target_os = "linux")]
    {
        kvm::is_available()
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        false
    }
}

/// Get the name of the backend for this platform.
pub fn name() -> Option<&'static str> {
    #[cfg(target_os = "macos")]
    {
        Some("hvf")
    }

    #[cfg(target_os = "windows")]
    {
        Some("wsl2")
    }

    #[cfg(target_os = "linux")]
    {
        Some("kvm")
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        None
    }
}

/// Create a platform-specific backend.
pub fn create(config: VmConfig) -> Result<Box<dyn HypervisorBackend>> {
    #[cfg(target_os = "macos")]
    {
        hvf::HvfBackend::new(config).map(|b| Box::new(b) as Box<dyn HypervisorBackend>)
    }

    #[cfg(target_os = "windows")]
    {
        wsl::WslBackend::new(config).map(|b| Box::new(b) as Box<dyn HypervisorBackend>)
    }

    #[cfg(target_os = "linux")]
    {
        kvm::KvmBackend::new(config).map(|b| Box::new(b) as Box<dyn HypervisorBackend>)
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        Err(crate::error::Error::HypervisorNotAvailable)
    }
}
