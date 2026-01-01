//! VM builder for configuring and creating MicroVMs.

use std::path::PathBuf;

use crate::backend;
use crate::error::{Error, Result};
use crate::vm::MicroVM;

/// Builder for creating a [`MicroVM`].
///
/// # Example
///
/// ```rust,no_run
/// use microvm::MicroVM;
///
/// let vm = MicroVM::builder()
///     .memory_mb(256)
///     .vcpus(2)
///     .kernel("/path/to/vmlinuz")
///     .cmdline("console=ttyS0")
///     .build()?;
/// # Ok::<(), microvm::Error>(())
/// ```
#[derive(Default)]
pub struct VmBuilder {
    memory_mb: Option<u32>,
    vcpus: Option<u32>,
    kernel: Option<PathBuf>,
    initrd: Option<PathBuf>,
    rootfs: Option<PathBuf>,
    cmdline: Option<String>,
}

impl VmBuilder {
    /// Create a new VM builder with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the amount of guest memory in megabytes.
    ///
    /// Default: 128 MB
    pub fn memory_mb(mut self, mb: u32) -> Self {
        self.memory_mb = Some(mb);
        self
    }

    /// Set the number of virtual CPUs.
    ///
    /// Default: 1
    pub fn vcpus(mut self, count: u32) -> Self {
        self.vcpus = Some(count);
        self
    }

    /// Set the path to the Linux kernel image.
    pub fn kernel(mut self, path: impl Into<PathBuf>) -> Self {
        self.kernel = Some(path.into());
        self
    }

    /// Set the path to the initial ramdisk (initrd).
    pub fn initrd(mut self, path: impl Into<PathBuf>) -> Self {
        self.initrd = Some(path.into());
        self
    }

    /// Set the path to the root filesystem image.
    pub fn rootfs(mut self, path: impl Into<PathBuf>) -> Self {
        self.rootfs = Some(path.into());
        self
    }

    /// Set the kernel command line.
    pub fn cmdline(mut self, cmdline: impl Into<String>) -> Self {
        self.cmdline = Some(cmdline.into());
        self
    }

    /// Build the MicroVM.
    ///
    /// This validates the configuration and creates the VM using the
    /// appropriate platform backend.
    pub fn build(self) -> Result<MicroVM> {
        // Validate configuration
        let memory_mb = self.memory_mb.unwrap_or(128);
        if memory_mb == 0 {
            return Err(Error::InvalidMemorySize(memory_mb));
        }

        let vcpus = self.vcpus.unwrap_or(1);
        if vcpus == 0 {
            return Err(Error::InvalidVcpuCount(vcpus));
        }

        // Validate kernel path if provided
        if let Some(ref kernel) = self.kernel {
            if !kernel.exists() {
                return Err(Error::KernelNotFound(kernel.clone()));
            }
        }

        // Validate rootfs path if provided
        if let Some(ref rootfs) = self.rootfs {
            if !rootfs.exists() {
                return Err(Error::RootfsNotFound(rootfs.clone()));
            }
        }

        // Create platform-specific backend
        let config = backend::VmConfig {
            memory_mb,
            vcpus,
            kernel: self.kernel,
            initrd: self.initrd,
            rootfs: self.rootfs,
            cmdline: self.cmdline.unwrap_or_default(),
        };

        let backend_impl = backend::create(config)?;
        let memory_size = (memory_mb as u64) * 1024 * 1024;

        Ok(MicroVM::new(backend_impl, memory_size, vcpus))
    }
}
