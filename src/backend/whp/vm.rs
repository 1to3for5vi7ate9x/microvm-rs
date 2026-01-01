//! WHP VM management.
//!
//! TODO: Implement on Windows machine.

use crate::backend::VmConfig;
use crate::error::{Error, Result};

#[cfg(target_os = "windows")]
use windows::Win32::System::Hypervisor::*;

/// Represents a WHP virtual machine partition.
pub struct Vm {
    #[cfg(target_os = "windows")]
    partition: WHV_PARTITION_HANDLE,

    #[cfg(not(target_os = "windows"))]
    _phantom: std::marker::PhantomData<()>,

    memory_size: usize,
    vcpu_count: u32,
}

impl Vm {
    /// Create a new VM with the given configuration.
    pub fn new(config: &VmConfig) -> Result<Self> {
        #[cfg(target_os = "windows")]
        {
            unsafe {
                // Create partition
                let mut partition = WHV_PARTITION_HANDLE::default();
                WHvCreatePartition(&mut partition).map_err(|e| {
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

                // Setup partition
                WHvSetupPartition(partition).map_err(|e| {
                    Error::HypervisorError(format!("Failed to setup partition: {:?}", e))
                })?;

                // Allocate and map guest memory
                let memory_size = (config.memory_mb as usize) * 1024 * 1024;
                let guest_memory = VirtualAlloc(
                    None,
                    memory_size,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_READWRITE,
                );

                if guest_memory.is_null() {
                    return Err(Error::MemoryAllocationFailed(
                        "VirtualAlloc failed".to_string(),
                    ));
                }

                // Map memory to guest
                WHvMapGpaRange(
                    partition,
                    guest_memory,
                    0, // Guest physical address
                    memory_size as u64,
                    WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite | WHvMapGpaRangeFlagExecute,
                )
                .map_err(|e| {
                    Error::HypervisorError(format!("Failed to map memory: {:?}", e))
                })?;

                // Create virtual processors
                for vp_index in 0..config.vcpus {
                    WHvCreateVirtualProcessor(partition, vp_index, 0).map_err(|e| {
                        Error::HypervisorError(format!(
                            "Failed to create vCPU {}: {:?}",
                            vp_index, e
                        ))
                    })?;
                }

                Ok(Self {
                    partition,
                    memory_size,
                    vcpu_count: config.vcpus,
                })
            }
        }

        #[cfg(not(target_os = "windows"))]
        {
            // Stub for non-Windows platforms
            Err(Error::HypervisorNotAvailable)
        }
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
