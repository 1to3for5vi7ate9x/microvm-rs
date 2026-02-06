//! MicroVM core implementation.

use crate::backend::HypervisorBackend;
use crate::error::{Error, Result};

/// The state of a MicroVM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmState {
    /// VM has been created but not started.
    Created,
    /// VM is currently booting.
    Booting,
    /// VM is running.
    Running,
    /// VM is paused.
    Paused,
    /// VM has been shut down.
    Shutdown,
    /// VM encountered a fatal error.
    Failed,
}

impl std::fmt::Display for VmState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VmState::Created => write!(f, "created"),
            VmState::Booting => write!(f, "booting"),
            VmState::Running => write!(f, "running"),
            VmState::Paused => write!(f, "paused"),
            VmState::Shutdown => write!(f, "shutdown"),
            VmState::Failed => write!(f, "failed"),
        }
    }
}

/// A lightweight virtual machine.
///
/// `MicroVM` provides a platform-agnostic interface to hardware-isolated
/// virtual machines. Use [`MicroVM::builder()`] to create a new VM.
///
/// # Example
///
/// ```rust,no_run
/// use microvm::MicroVM;
///
/// let vm = MicroVM::builder()
///     .memory_mb(128)
///     .build()?;
/// # Ok::<(), microvm::Error>(())
/// ```
pub struct MicroVM {
    /// Platform-specific backend
    backend: Box<dyn HypervisorBackend>,
    /// Current VM state
    state: VmState,
    /// Memory size in bytes
    memory_size: u64,
    /// Number of vCPUs
    vcpu_count: u32,
}

impl MicroVM {
    /// Create a new VM builder.
    pub fn builder() -> crate::builder::VmBuilder {
        crate::builder::VmBuilder::new()
    }

    /// Create a new MicroVM with the given backend.
    pub(crate) fn new(
        backend: Box<dyn HypervisorBackend>,
        memory_size: u64,
        vcpu_count: u32,
    ) -> Self {
        Self {
            backend,
            state: VmState::Created,
            memory_size,
            vcpu_count,
        }
    }

    /// Get the current state of the VM.
    pub fn state(&self) -> VmState {
        self.state
    }

    /// Get the memory size in bytes.
    pub fn memory_size(&self) -> u64 {
        self.memory_size
    }

    /// Get the number of vCPUs.
    pub fn vcpu_count(&self) -> u32 {
        self.vcpu_count
    }

    /// Boot the VM.
    ///
    /// This starts the VM's vCPUs and begins executing the guest code.
    pub fn boot(&mut self) -> Result<()> {
        match self.state {
            VmState::Created => {
                self.state = VmState::Booting;
                self.backend.start()?;
                self.state = VmState::Running;
                Ok(())
            }
            VmState::Running => Err(Error::AlreadyRunning),
            _ => Err(Error::InvalidState {
                expected: "created".to_string(),
                actual: self.state.to_string(),
            }),
        }
    }

    /// Pause the VM.
    pub fn pause(&mut self) -> Result<()> {
        match self.state {
            VmState::Running => {
                self.backend.pause()?;
                self.state = VmState::Paused;
                Ok(())
            }
            _ => Err(Error::InvalidState {
                expected: "running".to_string(),
                actual: self.state.to_string(),
            }),
        }
    }

    /// Resume a paused VM.
    pub fn resume(&mut self) -> Result<()> {
        match self.state {
            VmState::Paused => {
                self.backend.resume()?;
                self.state = VmState::Running;
                Ok(())
            }
            _ => Err(Error::InvalidState {
                expected: "paused".to_string(),
                actual: self.state.to_string(),
            }),
        }
    }

    /// Request graceful shutdown.
    ///
    /// This sends an ACPI power button event to the guest.
    pub fn shutdown(&mut self) -> Result<()> {
        match self.state {
            VmState::Running | VmState::Paused => {
                self.backend.shutdown()?;
                self.state = VmState::Shutdown;
                Ok(())
            }
            _ => Err(Error::NotRunning),
        }
    }

    /// Force kill the VM immediately.
    pub fn kill(&mut self) -> Result<()> {
        self.backend.kill()?;
        self.state = VmState::Shutdown;
        Ok(())
    }
}

impl Drop for MicroVM {
    fn drop(&mut self) {
        // Ensure VM is stopped when dropped
        if matches!(self.state, VmState::Running | VmState::Paused | VmState::Booting) {
            let _ = self.kill();
        }
    }
}

// Safety: MicroVM is thread-safe because:
// - All internal state access is through the backend which implements Send
// - State modifications are atomic or protected
// - The hypervisor frameworks (HVF, KVM) and WSL2 backend support multi-threaded access
unsafe impl Send for MicroVM {}
unsafe impl Sync for MicroVM {}
