//! Windows Hypervisor Platform (WHP) backend.
//!
//! This module provides virtualization support on Windows using the
//! Windows Hypervisor Platform API.
//!
//! ## Requirements
//!
//! - Windows 10 version 1803 or later
//! - Hyper-V enabled in Windows Features
//! - Virtualization enabled in BIOS/UEFI
//!
//! ## Development Notes
//!
//! This backend is developed on Windows. If you're on macOS/Linux,
//! the code will compile but the stubs won't be functional.

mod bindings;
mod memory;
mod vcpu;
mod vm;

use crate::backend::{HypervisorBackend, VmConfig};
use crate::error::{Error, Result};

pub use memory::GuestMemory;
pub use vcpu::Vcpu;
pub use vm::Vm;

/// Check if WHP is available on this system.
pub fn is_available() -> bool {
    #[cfg(target_os = "windows")]
    {
        // Try to get WHP capability to check if it's available
        bindings::check_whp_available()
    }

    #[cfg(not(target_os = "windows"))]
    {
        false
    }
}

/// Windows Hypervisor Platform backend implementation.
pub struct WhpBackend {
    vm: Vm,
    #[allow(dead_code)]
    config: VmConfig,
}

impl WhpBackend {
    /// Create a new WHP backend with the given configuration.
    pub fn new(config: VmConfig) -> Result<Self> {
        let vm = Vm::new(&config)?;
        Ok(Self { vm, config })
    }
}

impl HypervisorBackend for WhpBackend {
    fn start(&mut self) -> Result<()> {
        self.vm.start()
    }

    fn pause(&mut self) -> Result<()> {
        self.vm.pause()
    }

    fn resume(&mut self) -> Result<()> {
        self.vm.resume()
    }

    fn shutdown(&mut self) -> Result<()> {
        self.vm.shutdown()
    }

    fn kill(&mut self) -> Result<()> {
        self.vm.kill()
    }

    fn name(&self) -> &'static str {
        "whp"
    }
}
