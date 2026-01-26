//! macOS Hypervisor.framework backend.
//!
//! This module provides virtualization support on macOS using Apple's
//! Hypervisor.framework. It supports both Intel and Apple Silicon Macs.
//!
//! ## Requirements
//!
//! - macOS 10.10+ (Intel) or macOS 11+ (Apple Silicon)
//! - `com.apple.security.hypervisor` entitlement for App Store distribution
//!
//! ## Architecture
//!
//! The HVF backend consists of:
//! - `bindings` - Raw FFI bindings to Hypervisor.framework
//! - `vm` - VM creation and memory management
//! - `vcpu` - vCPU creation and execution
//! - `memory` - Guest physical memory mapping

pub mod bindings;
mod memory;
pub mod vcpu;
mod vm;

use crate::backend::{HypervisorBackend, VmConfig};
use crate::error::Result;

pub use memory::GuestMemory;
pub use vcpu::{Vcpu, VcpuExit};
#[cfg(target_arch = "aarch64")]
pub use vcpu::VcpuExitHandle;
pub use vm::Vm;

/// Check if Hypervisor.framework is available.
pub fn is_available() -> bool {
    // Try to create a VM context to check availability
    // This is a lightweight check that doesn't actually create a full VM
    unsafe {
        let result = bindings::hv_vm_create(bindings::HV_VM_DEFAULT);
        if result == bindings::HV_SUCCESS {
            // Clean up
            bindings::hv_vm_destroy();
            true
        } else {
            false
        }
    }
}

/// Hypervisor.framework backend implementation.
pub struct HvfBackend {
    vm: Vm,
    #[allow(dead_code)]
    config: VmConfig,
}

impl HvfBackend {
    /// Create a new HVF backend with the given configuration.
    pub fn new(config: VmConfig) -> Result<Self> {
        let vm = Vm::new(&config)?;
        Ok(Self { vm, config })
    }
}

impl HypervisorBackend for HvfBackend {
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
        #[cfg(target_arch = "x86_64")]
        {
            "hvf-x86_64"
        }
        #[cfg(target_arch = "aarch64")]
        {
            "hvf-aarch64"
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            "hvf"
        }
    }
}
