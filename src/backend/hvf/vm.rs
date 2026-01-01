//! HVF VM management.

use super::bindings::{self, hv_result, HV_MEMORY_EXEC, HV_MEMORY_READ, HV_MEMORY_WRITE};
use super::memory::GuestMemory;
use super::vcpu::Vcpu;
use crate::backend::VmConfig;
use crate::error::{Error, Result};

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Represents an HVF virtual machine.
pub struct Vm {
    /// Guest physical memory
    memory: GuestMemory,
    /// Virtual CPUs
    vcpus: Vec<Vcpu>,
    /// Whether the VM has been created
    created: bool,
    /// Whether the VM is running
    running: Arc<AtomicBool>,
}

impl Vm {
    /// Create a new VM with the given configuration.
    pub fn new(config: &VmConfig) -> Result<Self> {
        // Create VM context
        let ret = unsafe { bindings::hv_vm_create(bindings::HV_VM_DEFAULT) };
        hv_result(ret).map_err(|_| {
            Error::HypervisorError(format!(
                "Failed to create VM: {}",
                bindings::hv_return_string(ret)
            ))
        })?;

        // Allocate guest memory
        let memory_size = (config.memory_mb as usize) * 1024 * 1024;
        let memory = GuestMemory::new(memory_size)?;

        // Map memory into guest physical address space
        // ARM64: Start at 0x40000000 (1GB) to leave room for MMIO devices below
        // x86_64: Start at 0 for traditional PC memory map
        #[cfg(target_arch = "aarch64")]
        const RAM_BASE: u64 = 0x4000_0000; // 1GB - standard ARM64 virt machine layout
        #[cfg(target_arch = "x86_64")]
        const RAM_BASE: u64 = 0;

        let flags = HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC;
        let ret = unsafe {
            bindings::hv_vm_map(memory.as_ptr() as *mut _, RAM_BASE, memory.size(), flags)
        };
        hv_result(ret).map_err(|_| {
            Error::HypervisorError(format!(
                "Failed to map memory at 0x{:x}: {}",
                RAM_BASE,
                bindings::hv_return_string(ret)
            ))
        })?;

        // Note: With RAM at 0x40000000, MMIO regions (GIC at 0x08000000, UART at 0x09000000)
        // are naturally separate from RAM. No need to unmap anything - accesses to those
        // addresses will cause data abort exceptions that we handle as MMIO.

        // Create vCPUs
        let mut vcpus = Vec::with_capacity(config.vcpus as usize);
        for id in 0..config.vcpus {
            let vcpu = Vcpu::new(id)?;
            vcpus.push(vcpu);
        }

        Ok(Self {
            memory,
            vcpus,
            created: true,
            running: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Get a reference to guest memory.
    pub fn memory(&self) -> &GuestMemory {
        &self.memory
    }

    /// Get a mutable reference to guest memory.
    pub fn memory_mut(&mut self) -> &mut GuestMemory {
        &mut self.memory
    }

    /// Get a reference to a vCPU by index.
    pub fn vcpu(&self, index: usize) -> Option<&Vcpu> {
        self.vcpus.get(index)
    }

    /// Get a mutable reference to a vCPU by index.
    pub fn vcpu_mut(&mut self, index: usize) -> Option<&mut Vcpu> {
        self.vcpus.get_mut(index)
    }

    /// Start the VM.
    pub fn start(&mut self) -> Result<()> {
        if self.running.load(Ordering::SeqCst) {
            return Err(Error::AlreadyRunning);
        }

        self.running.store(true, Ordering::SeqCst);

        // For now, just run the first vCPU in the current thread
        // TODO: Spawn threads for each vCPU
        if let Some(vcpu) = self.vcpus.get_mut(0) {
            vcpu.run()?;
        }

        Ok(())
    }

    /// Pause the VM.
    pub fn pause(&mut self) -> Result<()> {
        // TODO: Implement vCPU interruption
        self.running.store(false, Ordering::SeqCst);
        Ok(())
    }

    /// Resume the VM.
    pub fn resume(&mut self) -> Result<()> {
        if self.running.load(Ordering::SeqCst) {
            return Err(Error::AlreadyRunning);
        }
        self.running.store(true, Ordering::SeqCst);
        // TODO: Resume vCPU execution
        Ok(())
    }

    /// Request graceful shutdown.
    pub fn shutdown(&mut self) -> Result<()> {
        // TODO: Send ACPI power button event
        self.running.store(false, Ordering::SeqCst);
        Ok(())
    }

    /// Force kill the VM.
    pub fn kill(&mut self) -> Result<()> {
        self.running.store(false, Ordering::SeqCst);
        // Interrupt all vCPUs
        // TODO: Implement proper interruption
        Ok(())
    }
}

impl Drop for Vm {
    fn drop(&mut self) {
        if self.created {
            // Destroy vCPUs first
            self.vcpus.clear();

            // Unmap memory
            let _ = unsafe { bindings::hv_vm_unmap(0, self.memory.size()) };

            // Destroy VM context
            let _ = unsafe { bindings::hv_vm_destroy() };
        }
    }
}
