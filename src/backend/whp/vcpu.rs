//! WHP vCPU management.
//!
//! TODO: Implement on Windows machine.

use crate::error::{Error, Result};

#[cfg(target_os = "windows")]
use windows::Win32::System::Hypervisor::*;

/// Exit reason from vCPU execution.
#[derive(Debug, Clone)]
pub enum VcpuExit {
    /// I/O port read
    IoIn { port: u16, size: u8 },
    /// I/O port write
    IoOut { port: u16, data: Vec<u8> },
    /// Memory-mapped I/O read
    MmioRead { addr: u64, size: u8 },
    /// Memory-mapped I/O write
    MmioWrite { addr: u64, data: Vec<u8> },
    /// Guest executed HLT instruction
    Hlt,
    /// Guest shutdown
    Shutdown,
    /// Execution was canceled
    Canceled,
    /// Unknown exit reason
    Unknown(i32),
}

/// Represents a WHP virtual processor.
pub struct Vcpu {
    #[cfg(target_os = "windows")]
    partition: WHV_PARTITION_HANDLE,
    index: u32,
}

impl Vcpu {
    /// Create a new vCPU reference.
    #[cfg(target_os = "windows")]
    pub fn new(partition: WHV_PARTITION_HANDLE, index: u32) -> Self {
        Self { partition, index }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn new(index: u32) -> Self {
        Self { index }
    }

    /// Get the vCPU index.
    pub fn index(&self) -> u32 {
        self.index
    }

    /// Run the vCPU until an exit occurs.
    #[cfg(target_os = "windows")]
    pub fn run(&mut self) -> Result<VcpuExit> {
        use super::bindings::exit_reason::*;

        unsafe {
            let mut exit_context = WHV_RUN_VP_EXIT_CONTEXT::default();
            WHvRunVirtualProcessor(
                self.partition,
                self.index,
                &mut exit_context as *mut _ as *mut _,
                std::mem::size_of::<WHV_RUN_VP_EXIT_CONTEXT>() as u32,
            )
            .map_err(|e| Error::VcpuError(format!("WHvRunVirtualProcessor failed: {:?}", e)))?;

            match exit_context.ExitReason.0 {
                WHV_RUN_VP_EXIT_REASON_X64_HALT => Ok(VcpuExit::Hlt),
                WHV_RUN_VP_EXIT_REASON_X64_IO_PORT_ACCESS => {
                    let io_port = exit_context.Anonymous.IoPortAccess;
                    let port = io_port.PortNumber;
                    let size = io_port.AccessInfo.AccessSize() as u8;
                    let is_write = io_port.AccessInfo.IsWrite() != 0;

                    if is_write {
                        let data = io_port.Rax.to_le_bytes()[..size as usize].to_vec();
                        Ok(VcpuExit::IoOut { port, data })
                    } else {
                        Ok(VcpuExit::IoIn { port, size })
                    }
                }
                WHV_RUN_VP_EXIT_REASON_MEMORY_ACCESS => {
                    let mem_access = exit_context.Anonymous.MemoryAccess;
                    let addr = mem_access.Gpa;
                    let is_write = mem_access.AccessInfo.AccessType() == 1;

                    if is_write {
                        Ok(VcpuExit::MmioWrite {
                            addr,
                            data: vec![], // TODO: Extract actual data
                        })
                    } else {
                        Ok(VcpuExit::MmioRead {
                            addr,
                            size: 4, // TODO: Get actual size
                        })
                    }
                }
                WHV_RUN_VP_EXIT_REASON_CANCELED => Ok(VcpuExit::Canceled),
                other => Ok(VcpuExit::Unknown(other)),
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn run(&mut self) -> Result<VcpuExit> {
        Err(Error::HypervisorNotAvailable)
    }

    /// Read a register value.
    #[cfg(target_os = "windows")]
    pub fn read_register(&self, reg: WHV_REGISTER_NAME) -> Result<u64> {
        unsafe {
            let reg_names = [reg];
            let mut reg_values = [WHV_REGISTER_VALUE::default()];

            WHvGetVirtualProcessorRegisters(
                self.partition,
                self.index,
                reg_names.as_ptr(),
                1,
                reg_values.as_mut_ptr(),
            )
            .map_err(|e| Error::VcpuError(format!("Failed to read register: {:?}", e)))?;

            Ok(reg_values[0].Reg64)
        }
    }

    /// Write a register value.
    #[cfg(target_os = "windows")]
    pub fn write_register(&self, reg: WHV_REGISTER_NAME, value: u64) -> Result<()> {
        unsafe {
            let reg_names = [reg];
            let reg_values = [WHV_REGISTER_VALUE { Reg64: value }];

            WHvSetVirtualProcessorRegisters(
                self.partition,
                self.index,
                reg_names.as_ptr(),
                1,
                reg_values.as_ptr(),
            )
            .map_err(|e| Error::VcpuError(format!("Failed to write register: {:?}", e)))?;

            Ok(())
        }
    }
}
