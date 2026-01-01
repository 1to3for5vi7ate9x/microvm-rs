//! Linux KVM backend.
//!
//! This module provides virtualization support on Linux using KVM.
//! It leverages the rust-vmm ecosystem for low-level KVM access.
//!
//! ## Requirements
//!
//! - Linux kernel with KVM support
//! - Access to /dev/kvm
//! - CPU with VT-x (Intel) or AMD-V (AMD)
//!
//! ## Status
//!
//! This backend is a placeholder. Implementation will be added
//! after macOS and Windows backends are complete.

use crate::backend::{HypervisorBackend, VmConfig};
use crate::error::{Error, Result};

/// Check if KVM is available on this system.
pub fn is_available() -> bool {
    #[cfg(target_os = "linux")]
    {
        std::path::Path::new("/dev/kvm").exists()
    }

    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// KVM backend implementation.
pub struct KvmBackend {
    #[allow(dead_code)]
    config: VmConfig,
}

impl KvmBackend {
    /// Create a new KVM backend with the given configuration.
    pub fn new(config: VmConfig) -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            // TODO: Implement KVM backend
            // For now, just store the config
            Ok(Self { config })
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = config;
            Err(Error::HypervisorNotAvailable)
        }
    }
}

impl HypervisorBackend for KvmBackend {
    fn start(&mut self) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            // TODO: Implement
            Ok(())
        }

        #[cfg(not(target_os = "linux"))]
        {
            Err(Error::HypervisorNotAvailable)
        }
    }

    fn pause(&mut self) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            Ok(())
        }

        #[cfg(not(target_os = "linux"))]
        {
            Err(Error::HypervisorNotAvailable)
        }
    }

    fn resume(&mut self) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            Ok(())
        }

        #[cfg(not(target_os = "linux"))]
        {
            Err(Error::HypervisorNotAvailable)
        }
    }

    fn shutdown(&mut self) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            Ok(())
        }

        #[cfg(not(target_os = "linux"))]
        {
            Err(Error::HypervisorNotAvailable)
        }
    }

    fn kill(&mut self) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            Ok(())
        }

        #[cfg(not(target_os = "linux"))]
        {
            Err(Error::HypervisorNotAvailable)
        }
    }

    fn name(&self) -> &'static str {
        "kvm"
    }
}
