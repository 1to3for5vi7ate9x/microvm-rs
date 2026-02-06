//! Error types for microvm.

use std::path::PathBuf;
use thiserror::Error;

/// Result type alias using microvm's Error type.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur when working with microVMs.
#[derive(Error, Debug)]
pub enum Error {
    // Platform/hypervisor errors
    #[error("hypervisor not available on this platform")]
    HypervisorNotAvailable,

    #[error("hypervisor error: {0}")]
    HypervisorError(String),

    #[error("virtualization not supported by CPU")]
    VirtualizationNotSupported,

    #[error("insufficient permissions to access hypervisor")]
    PermissionDenied,

    // Configuration errors
    #[error("invalid memory size: {0} MB (must be > 0)")]
    InvalidMemorySize(u32),

    #[error("invalid vCPU count: {0} (must be > 0)")]
    InvalidVcpuCount(u32),

    #[error("kernel not found: {0}")]
    KernelNotFound(PathBuf),

    #[error("invalid kernel format: {0}")]
    InvalidKernel(String),

    #[error("rootfs not found: {0}")]
    RootfsNotFound(PathBuf),

    // Runtime errors
    #[error("VM not in expected state: expected {expected}, got {actual}")]
    InvalidState { expected: String, actual: String },

    #[error("VM already running")]
    AlreadyRunning,

    #[error("VM not running")]
    NotRunning,

    #[error("vCPU error: {0}")]
    VcpuError(String),

    // Device errors
    #[error("device error: {0}")]
    DeviceError(String),

    #[error("device not found: {0}")]
    DeviceNotFound(String),

    // Memory errors
    #[error("memory allocation failed: {0}")]
    MemoryAllocationFailed(String),

    #[error("invalid guest address: 0x{0:x}")]
    InvalidGuestAddress(u64),

    // I/O errors
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    // Platform-specific errors
    #[cfg(target_os = "macos")]
    #[error("Hypervisor.framework error: {0}")]
    HvfError(i32),

    #[cfg(target_os = "windows")]
    #[error("WSL error: {0}")]
    WslError(String),

    #[cfg(target_os = "linux")]
    #[error("KVM error: {0}")]
    KvmError(String),

    // Network errors
    #[error("vmnet error: {0}")]
    Vmnet(String),

    #[error("feature not supported: {0}")]
    NotSupported(String),
}

impl Error {
    /// Create a hypervisor error from a platform-specific error code.
    #[cfg(target_os = "macos")]
    pub fn from_hvf(code: i32) -> Self {
        Error::HvfError(code)
    }

    #[cfg(target_os = "windows")]
    pub fn from_wsl(msg: impl Into<String>) -> Self {
        Error::WslError(msg.into())
    }

    #[cfg(target_os = "linux")]
    pub fn from_kvm(msg: impl Into<String>) -> Self {
        Error::KvmError(msg.into())
    }
}
