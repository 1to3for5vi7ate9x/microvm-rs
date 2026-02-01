//! WHP VM management.

use crate::backend::VmConfig;
use crate::error::{Error, Result};
use super::memory::GuestMemory;
use super::vcpu::Vcpu;

#[cfg(target_os = "windows")]
use windows::Win32::System::Hypervisor::*;

/// Represents a WHP virtual machine partition.
pub struct Vm {
    #[cfg(target_os = "windows")]
    partition: WHV_PARTITION_HANDLE,

    #[cfg(not(target_os = "windows"))]
    _phantom: std::marker::PhantomData<()>,

    /// Guest physical memory
    memory: GuestMemory,
    /// Virtual CPUs
    vcpus: Vec<Vcpu>,
    vcpu_count: u32,
}

impl Vm {
    /// Create a new VM with the given configuration.
    pub fn new(config: &VmConfig) -> Result<Self> {
        #[cfg(target_os = "windows")]
        {
            unsafe {
                // Create partition
                let partition = WHvCreatePartition().map_err(|e| {
                    Error::HypervisorError(format!("Failed to create partition: {:?}", e))
                })?;

                // Set processor count
                let processor_count = WHV_PARTITION_PROPERTY {
                    ProcessorCount: config.vcpus,
                };
                WHvSetPartitionProperty(
                    partition,
                    WHvPartitionPropertyCodeProcessorCount,
                    &processor_count as *const _ as *const _,
                    std::mem::size_of::<WHV_PARTITION_PROPERTY>() as u32,
                )
                .map_err(|e| {
                    Error::HypervisorError(format!("Failed to set processor count: {:?}", e))
                })?;

                // Enable extended VM exits for CPUID and MSR
                // We enable MSR exits so we can handle unimplemented MSRs gracefully
                // instead of having WHP inject GP faults into the guest.
                let mut extended_exits = WHV_PARTITION_PROPERTY::default();
                // WHV_EXTENDED_VM_EXITS bitfield:
                // Bit 0: X64CpuidExit, Bit 1: X64MsrExit, Bit 2: ExceptionExit, Bit 3: X64RdtscExit
                extended_exits.ExtendedVmExits.Anonymous._bitfield = 0x3; // CPUID + MSR exits
                WHvSetPartitionProperty(
                    partition,
                    WHvPartitionPropertyCodeExtendedVmExits,
                    &extended_exits as *const _ as *const _,
                    std::mem::size_of::<WHV_PARTITION_PROPERTY>() as u32,
                )
                .map_err(|e| {
                    Error::HypervisorError(format!("Failed to enable extended VM exits: {:?}", e))
                })?;

                // Configure unimplemented MSR action to exit to VMM instead of GP fault
                // This allows us to handle unknown MSRs gracefully
                let mut msr_action = WHV_PARTITION_PROPERTY::default();
                // WHV_MSR_ACTION: 0 = GP fault, 1 = Exit to VMM
                msr_action.UnimplementedMsrAction = WHV_MSR_ACTION(1);
                WHvSetPartitionProperty(
                    partition,
                    WHvPartitionPropertyCodeUnimplementedMsrAction,
                    &msr_action as *const _ as *const _,
                    std::mem::size_of::<WHV_PARTITION_PROPERTY>() as u32,
                )
                .map_err(|e| {
                    Error::HypervisorError(format!("Failed to set MSR action: {:?}", e))
                })?;

                // Enable Local APIC emulation in xAPIC mode
                // This is needed for timer interrupts and proper kernel boot
                let mut apic_mode = WHV_PARTITION_PROPERTY::default();
                apic_mode.LocalApicEmulationMode = WHV_X64_LOCAL_APIC_EMULATION_MODE(1); // xAPIC mode
                WHvSetPartitionProperty(
                    partition,
                    WHvPartitionPropertyCodeLocalApicEmulationMode,
                    &apic_mode as *const _ as *const _,
                    std::mem::size_of::<WHV_PARTITION_PROPERTY>() as u32,
                )
                .map_err(|e| {
                    Error::HypervisorError(format!("Failed to set APIC emulation mode: {:?}", e))
                })?;

                // Setup partition
                WHvSetupPartition(partition).map_err(|e| {
                    Error::HypervisorError(format!("Failed to setup partition: {:?}", e))
                })?;

                // Allocate guest memory
                let memory_size = (config.memory_mb as usize) * 1024 * 1024;
                let memory = GuestMemory::new(memory_size)?;

                // Map memory to guest physical address space
                WHvMapGpaRange(
                    partition,
                    memory.as_ptr() as *const std::ffi::c_void,
                    0, // Guest physical address
                    memory_size as u64,
                    WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite | WHvMapGpaRangeFlagExecute,
                )
                .map_err(|e| {
                    Error::HypervisorError(format!("Failed to map memory: {:?}", e))
                })?;

                // Create virtual processors
                let mut vcpus = Vec::with_capacity(config.vcpus as usize);
                for vp_index in 0..config.vcpus {
                    WHvCreateVirtualProcessor(partition, vp_index, 0).map_err(|e| {
                        Error::HypervisorError(format!(
                            "Failed to create vCPU {}: {:?}",
                            vp_index, e
                        ))
                    })?;
                    vcpus.push(Vcpu::new(partition, vp_index));
                }

                Ok(Self {
                    partition,
                    memory,
                    vcpus,
                    vcpu_count: config.vcpus,
                })
            }
        }

        #[cfg(not(target_os = "windows"))]
        {
            let _ = config;
            // Stub for non-Windows platforms
            Err(Error::HypervisorNotAvailable)
        }
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

    /// Get the number of vCPUs.
    pub fn vcpu_count(&self) -> u32 {
        self.vcpu_count
    }

    /// Start the VM.
    pub fn start(&mut self) -> Result<()> {
        #[cfg(target_os = "windows")]
        {
            // TODO: Run vCPU loop
            Ok(())
        }

        #[cfg(not(target_os = "windows"))]
        {
            Err(Error::HypervisorNotAvailable)
        }
    }

    /// Pause the VM.
    pub fn pause(&mut self) -> Result<()> {
        #[cfg(target_os = "windows")]
        {
            // TODO: Cancel vCPU execution
            Ok(())
        }

        #[cfg(not(target_os = "windows"))]
        {
            Err(Error::HypervisorNotAvailable)
        }
    }

    /// Resume the VM.
    pub fn resume(&mut self) -> Result<()> {
        #[cfg(target_os = "windows")]
        {
            // TODO: Resume vCPU execution
            Ok(())
        }

        #[cfg(not(target_os = "windows"))]
        {
            Err(Error::HypervisorNotAvailable)
        }
    }

    /// Request graceful shutdown.
    pub fn shutdown(&mut self) -> Result<()> {
        #[cfg(target_os = "windows")]
        {
            // TODO: Send shutdown signal
            Ok(())
        }

        #[cfg(not(target_os = "windows"))]
        {
            Err(Error::HypervisorNotAvailable)
        }
    }

    /// Force kill the VM.
    pub fn kill(&mut self) -> Result<()> {
        #[cfg(target_os = "windows")]
        {
            // Cancel all vCPU execution
            unsafe {
                for vp_index in 0..self.vcpu_count {
                    let _ = WHvCancelRunVirtualProcessor(self.partition, vp_index, 0);
                }
            }
            Ok(())
        }

        #[cfg(not(target_os = "windows"))]
        {
            Err(Error::HypervisorNotAvailable)
        }
    }
}

#[cfg(target_os = "windows")]
impl Drop for Vm {
    fn drop(&mut self) {
        unsafe {
            // Delete virtual processors
            for vp_index in 0..self.vcpu_count {
                let _ = WHvDeleteVirtualProcessor(self.partition, vp_index);
            }

            // Delete partition
            let _ = WHvDeletePartition(self.partition);
        }
    }
}

#[cfg(not(target_os = "windows"))]
impl Drop for Vm {
    fn drop(&mut self) {
        // Nothing to clean up on non-Windows
    }
}
