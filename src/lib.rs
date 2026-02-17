//! # microvm
//!
//! A cross-platform, embeddable microVM library for Rust.
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use microvm::{MicroVM, Result};
//!
//! fn main() -> Result<()> {
//!     let vm = MicroVM::builder()
//!         .memory_mb(128)
//!         .build()?;
//!
//!     // VM is ready to use
//!     Ok(())
//! }
//! ```
//!
//! ## Platform Support
//!
//! - **macOS**: Hypervisor.framework (Intel + Apple Silicon)
//! - **Windows**: WSL2 (Windows Subsystem for Linux)
//! - **Linux**: KVM (future)

mod builder;
pub mod debug;
mod error;
mod vm;
pub mod runner;
pub mod runtime;

pub mod backend;
pub mod device;
pub mod loader;
pub mod memory;
pub mod proxy;
pub mod vsock;

// Re-exports
pub use builder::VmBuilder;
pub use error::{Error, Result};
pub use vm::{MicroVM, VmState};
pub use vsock::{VsockClient, VsockConnection, VsockHandler, VsockMessage, create_vsock_channel};
pub use runtime::{VmRuntime, RuntimeConfig, RuntimeHandle};
pub use proxy::{ProxyConnectionManager, OUTBOUND_PROXY_PORT};

/// Spawn an interactive shell inside the VM (WSL2 backend, piped stdio).
///
/// Convenience re-export for Velocitty integration.
#[cfg(target_os = "windows")]
pub use backend::wsl::spawn_shell as spawn_vm_shell;

/// Full cleanup of the WSL2 distro and its on-disk data.
///
/// Terminates the running distro, unregisters it (deletes the ext4.vhdx),
/// and removes the `%LOCALAPPDATA%\microvm-rs\` directory.
/// Best-effort — individual failures are logged but do not block the rest.
#[cfg(target_os = "windows")]
pub use backend::wsl::cleanup as cleanup_vm;

/// Check if the current platform supports hardware virtualization.
///
/// Returns `true` if the hypervisor is available and can be used.
pub fn is_supported() -> bool {
    backend::is_available()
}

/// Get the name of the hypervisor backend for the current platform.
///
/// Returns `None` if no backend is available.
pub fn backend_name() -> Option<&'static str> {
    backend::name()
}
