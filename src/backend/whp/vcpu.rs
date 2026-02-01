//! WHP vCPU management.

use crate::error::{Error, Result};

#[cfg(target_os = "windows")]
use windows::Win32::System::Hypervisor::*;

/// Exit reason from vCPU execution.
#[derive(Debug, Clone)]
pub enum VcpuExit {
    /// I/O port read
    IoIn { port: u16, size: u8, instruction_len: u8 },
    /// I/O port write
    IoOut { port: u16, data: Vec<u8>, instruction_len: u8 },
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
    /// CPUID instruction
    Cpuid { rax: u64, rcx: u64, instruction_len: u8 },
    /// MSR read
    MsrRead { msr: u32, instruction_len: u8 },
    /// MSR write
    MsrWrite { msr: u32, value: u64, instruction_len: u8 },
    /// RDTSC instruction
    Rdtsc { instruction_len: u8 },
    /// Unrecoverable exception (triple fault, etc.)
    Exception { exception_type: u8, error_code: u32, rip: u64 },
    /// Intercepted exception (from exception bitmap)
    InterceptedException { exception_type: u8, error_code: u32, rip: u64, parameter: u64 },
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

    /// Initialize vCPU for 64-bit long mode boot.
    /// This sets up the processor state for booting a Linux kernel.
    #[cfg(target_os = "windows")]
    pub fn init_long_mode(&self, entry_point: u64, boot_params_addr: u64) -> Result<()> {
        // Enable long mode in EFER
        // EFER.LME (bit 8) = Long Mode Enable
        // EFER.LMA (bit 10) = Long Mode Active
        self.write_register(WHvX64RegisterEfer, 0x500)?; // EFER: LME | LMA

        // Set up CR0: PE (bit 0), ET (bit 4), PG (bit 31)
        // PE = Protected Mode Enable
        // ET = Extension Type (x87 FPU is present)
        // PG = Paging Enable
        self.write_register(WHvX64RegisterCr0, 0x80000011)?;

        // Set up CR4: PAE (bit 5) = Physical Address Extension (required for long mode)
        self.write_register(WHvX64RegisterCr4, 0x20)?;

        // Set up CR3 (page table base) - identity mapping at 0x1000
        self.write_register(WHvX64RegisterCr3, 0x1000)?;

        // Set up segment registers for 64-bit mode - Linux boot protocol requires:
        // __BOOT_CS = 0x10 (GDT entry 2)
        // __BOOT_DS = 0x18 (GDT entry 3)
        // GDT layout at 0x500: null (0x00), reserved (0x08), code64 (0x10), data64 (0x18)
        self.write_segment(WHvX64RegisterCs, 0x10, 0, 0xFFFFFFFF, 0xA09B)?; // 64-bit code (__BOOT_CS)
        self.write_segment(WHvX64RegisterDs, 0x18, 0, 0xFFFFFFFF, 0xC093)?; // 64-bit data (__BOOT_DS)
        self.write_segment(WHvX64RegisterEs, 0x18, 0, 0xFFFFFFFF, 0xC093)?;
        self.write_segment(WHvX64RegisterSs, 0x18, 0, 0xFFFFFFFF, 0xC093)?;
        self.write_segment(WHvX64RegisterFs, 0x18, 0, 0xFFFFFFFF, 0xC093)?;
        self.write_segment(WHvX64RegisterGs, 0x18, 0, 0xFFFFFFFF, 0xC093)?;

        // Set up GDT register (base=0x500, limit=31 for 4 entries)
        self.write_table_register(WHvX64RegisterGdtr, 0x500, 31)?;

        // Set up IDT register (empty for now)
        self.write_table_register(WHvX64RegisterIdtr, 0, 0)?;

        // Set up RFLAGS (reserved bit 1 must be set)
        self.write_register(WHvX64RegisterRflags, 0x2)?;

        // Set up RIP (entry point)
        self.write_register(WHvX64RegisterRip, entry_point)?;

        // Set up RSP (stack pointer) - use top of low memory
        self.write_register(WHvX64RegisterRsp, 0x8000)?;

        // Set up RSI to point to boot params (Linux boot protocol)
        self.write_register(WHvX64RegisterRsi, boot_params_addr)?;

        // Zero out other general purpose registers
        self.write_register(WHvX64RegisterRax, 0)?;
        self.write_register(WHvX64RegisterRbx, 0)?;
        self.write_register(WHvX64RegisterRcx, 0)?;
        self.write_register(WHvX64RegisterRdx, 0)?;
        self.write_register(WHvX64RegisterRdi, 0)?;
        self.write_register(WHvX64RegisterRbp, 0)?;

        Ok(())
    }

    /// Write a segment register with full descriptor.
    #[cfg(target_os = "windows")]
    pub fn write_segment(&self, reg: WHV_REGISTER_NAME, selector: u16, base: u64, limit: u32, attributes: u16) -> Result<()> {
        unsafe {
            let reg_names = [reg];
            let mut reg_value = WHV_REGISTER_VALUE::default();
            reg_value.Segment.Selector = selector;
            reg_value.Segment.Base = base;
            reg_value.Segment.Limit = limit;
            reg_value.Segment.Anonymous.Attributes = attributes;
            let reg_values = [reg_value];

            WHvSetVirtualProcessorRegisters(
                self.partition,
                self.index,
                reg_names.as_ptr(),
                1,
                reg_values.as_ptr(),
            )
            .map_err(|e| Error::VcpuError(format!("Failed to write segment register: {:?}", e)))?;

            Ok(())
        }
    }

    /// Write a table register (GDT or IDT).
    #[cfg(target_os = "windows")]
    pub fn write_table_register(&self, reg: WHV_REGISTER_NAME, base: u64, limit: u16) -> Result<()> {
        unsafe {
            let reg_names = [reg];
            let mut reg_value = WHV_REGISTER_VALUE::default();
            reg_value.Table.Base = base;
            reg_value.Table.Limit = limit;
            let reg_values = [reg_value];

            WHvSetVirtualProcessorRegisters(
                self.partition,
                self.index,
                reg_names.as_ptr(),
                1,
                reg_values.as_ptr(),
            )
            .map_err(|e| Error::VcpuError(format!("Failed to write table register: {:?}", e)))?;

            Ok(())
        }
    }

    /// Initialize vCPU for real mode (16-bit) boot - simpler setup.
    #[cfg(target_os = "windows")]
    pub fn init_real_mode(&self) -> Result<()> {
        // Set up CR0: ET bit only (no protected mode)
        self.write_register(WHvX64RegisterCr0, 0x10)?;

        // Set up RFLAGS (reserved bit 1 must be set)
        self.write_register(WHvX64RegisterRflags, 0x2)?;

        // RIP starts at 0
        self.write_register(WHvX64RegisterRip, 0)?;

        Ok(())
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

                    // WHV_X64_IO_PORT_ACCESS_INFO bitfield (Windows SDK):
                    // Bit 0: IsWrite
                    // Bits 1-3: AccessSize (0=1byte, 1=2bytes, 2=4bytes)
                    // Bit 4: StringOp
                    // Bit 5: RepPrefix
                    let access_info = io_port.AccessInfo.Anonymous._bitfield;
                    let is_write = (access_info & 0x1) != 0; // bit 0
                    let access_size_code = ((access_info >> 1) & 0x7) as u8; // bits 1-3
                    let size = match access_size_code {
                        0 => 1u8,  // 1 byte
                        1 => 2u8,  // 2 bytes
                        _ => 4u8,  // 4 bytes
                    };

                    // Get instruction length from VpContext
                    // WHV_VP_EXECUTION_STATE is at VpContext.ExecutionState
                    // The InstructionByteCount is encoded in the bitfield
                    // Bits 4-7 contain the instruction byte count (0-15 bytes)
                    let exec_state = exit_context.VpContext.ExecutionState.Anonymous._bitfield;
                    let instruction_len = ((exec_state >> 4) & 0xF) as u8;
                    // Fallback to reasonable defaults if instruction length is 0
                    let instruction_len = if instruction_len == 0 {
                        // String op with prefix could be longer, simple I/O is 1-2 bytes
                        if (access_info & 0x10) != 0 { 2 } else { 1 }
                    } else {
                        instruction_len
                    };

                    if is_write {
                        let data = io_port.Rax.to_le_bytes()[..size as usize].to_vec();
                        Ok(VcpuExit::IoOut { port, data, instruction_len })
                    } else {
                        Ok(VcpuExit::IoIn { port, size, instruction_len })
                    }
                }
                WHV_RUN_VP_EXIT_REASON_MEMORY_ACCESS => {
                    let mem_access = exit_context.Anonymous.MemoryAccess;
                    let addr = mem_access.Gpa;
                    // AccessInfo is a bitfield union - access raw bits
                    // Bits 0-1: AccessType (0=read, 1=write)
                    let access_info = mem_access.AccessInfo.Anonymous._bitfield;
                    let is_write = (access_info & 0x3) == 1;

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
                WHV_RUN_VP_EXIT_REASON_X64_CPUID => {
                    let cpuid = exit_context.Anonymous.CpuidAccess;
                    // Get instruction length from exit context
                    let exec_state = exit_context.VpContext.ExecutionState.Anonymous._bitfield;
                    let instruction_len = ((exec_state >> 4) & 0xF) as u8;
                    // CPUID (0F A2) is always 2 bytes, force minimum of 2
                    let instruction_len = if instruction_len < 2 { 2 } else { instruction_len };
                    Ok(VcpuExit::Cpuid {
                        rax: cpuid.Rax,
                        rcx: cpuid.Rcx,
                        instruction_len,
                    })
                }
                WHV_RUN_VP_EXIT_REASON_X64_MSR_ACCESS => {
                    let msr_access = exit_context.Anonymous.MsrAccess;

                    // Get instruction length from exit context (CRITICAL - don't hardcode!)
                    let exec_state = exit_context.VpContext.ExecutionState.Anonymous._bitfield;
                    let instruction_len = ((exec_state >> 4) & 0xF) as u8;
                    // RDMSR (0F 32) and WRMSR (0F 30) are always 2 bytes
                    // WHP may report incorrect lengths, so force minimum of 2
                    let instruction_len = if instruction_len < 2 { 2 } else { instruction_len };

                    // AccessInfo bit 0: IsWrite
                    let access_info = msr_access.AccessInfo.Anonymous._bitfield;
                    let is_write = (access_info & 0x1) != 0;

                    // Get MSR number from context (this is the authoritative source per WHP docs)
                    let msr_from_context = msr_access.MsrNumber;

                    // Read RCX as fallback - but DON'T read other registers unnecessarily
                    // to avoid any potential side effects
                    let rcx = {
                        let reg_names = [WHvX64RegisterRcx];
                        let mut reg_values = [WHV_REGISTER_VALUE::default(); 1];
                        let _ = WHvGetVirtualProcessorRegisters(
                            self.partition,
                            self.index,
                            reg_names.as_ptr(),
                            1,
                            reg_values.as_mut_ptr(),
                        );
                        reg_values[0].Reg64
                    };

                    // Determine MSR number - prefer context, fallback to RCX
                    let msr = if msr_from_context != 0 {
                        msr_from_context
                    } else if rcx != 0 {
                        rcx as u32
                    } else {
                        0 // Unknown MSR
                    };

                    // WHP BUG WORKAROUND: The exit context's Rax/Rdx fields may contain garbage
                    // (often the MSR number instead of the actual value). We must read the
                    // actual register values from the vCPU state.
                    let (actual_rax, actual_rdx) = if is_write {
                        let reg_names = [WHvX64RegisterRax, WHvX64RegisterRdx];
                        let mut reg_values = [WHV_REGISTER_VALUE::default(); 2];
                        let _ = WHvGetVirtualProcessorRegisters(
                            self.partition,
                            self.index,
                            reg_names.as_ptr(),
                            2,
                            reg_values.as_mut_ptr(),
                        );
                        (reg_values[0].Reg64, reg_values[1].Reg64)
                    } else {
                        (0, 0)
                    };

                    // Debug: Print MSR access info (limit output)
                    static DEBUG_COUNT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
                    let count = DEBUG_COUNT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    if count < 50 {
                        let rip = exit_context.VpContext.Rip;
                        if is_write {
                            eprintln!("[MSR] 0x{:x} WRITE msr=0x{:x} (RCX=0x{:x}, RAX=0x{:x}, RDX=0x{:x}, len={})",
                                rip, msr, rcx, actual_rax, actual_rdx, instruction_len);
                        } else {
                            eprintln!("[MSR] 0x{:x} READ msr=0x{:x} (RCX=0x{:x}, len={})",
                                rip, msr, rcx, instruction_len);
                        }
                    }

                    if is_write {
                        Ok(VcpuExit::MsrWrite {
                            msr,
                            value: actual_rax | (actual_rdx << 32),
                            instruction_len,
                        })
                    } else {
                        Ok(VcpuExit::MsrRead { msr, instruction_len })
                    }
                }
                WHV_RUN_VP_EXIT_REASON_CANCELED => Ok(VcpuExit::Canceled),
                WHV_RUN_VP_EXIT_REASON_EXCEPTION => {
                    // Intercepted exception (from exception bitmap)
                    let exception = exit_context.Anonymous.VpException;
                    let exception_type = exception.ExceptionType as u8;
                    let error_code = exception.ErrorCode;
                    let parameter = exception.ExceptionParameter;
                    let rip = exit_context.VpContext.Rip;
                    Ok(VcpuExit::InterceptedException { exception_type, error_code, rip, parameter })
                }
                WHV_RUN_VP_EXIT_REASON_UNRECOVERABLE_EXCEPTION => {
                    // Extract exception info from VpException field
                    let exception = exit_context.Anonymous.VpException;
                    let exception_type = exception.ExceptionType as u8;
                    let error_code = exception.ErrorCode;
                    let rip = exit_context.VpContext.Rip;
                    Ok(VcpuExit::Exception { exception_type, error_code, rip })
                }
                WHV_RUN_VP_EXIT_REASON_X64_RDTSC => {
                    let exec_state = exit_context.VpContext.ExecutionState.Anonymous._bitfield;
                    let instruction_len = ((exec_state >> 4) & 0xF) as u8;
                    // RDTSC (0F 31) is always 2 bytes, force minimum of 2
                    let instruction_len = if instruction_len < 2 { 2 } else { instruction_len };
                    Ok(VcpuExit::Rdtsc { instruction_len })
                }
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

    /// Set RAX register (used for I/O IN response).
    #[cfg(target_os = "windows")]
    pub fn set_rax(&self, value: u64) -> Result<()> {
        self.write_register(WHvX64RegisterRax, value)
    }

    /// Get RAX register value.
    #[cfg(target_os = "windows")]
    pub fn get_rax(&self) -> Result<u64> {
        self.read_register(WHvX64RegisterRax)
    }

    /// Set CPUID result registers (EAX, EBX, ECX, EDX).
    #[cfg(target_os = "windows")]
    pub fn set_cpuid_result(&self, eax: u32, ebx: u32, ecx: u32, edx: u32) -> Result<()> {
        // Write lower 32 bits of each register
        self.write_register(WHvX64RegisterRax, eax as u64)?;
        self.write_register(WHvX64RegisterRbx, ebx as u64)?;
        self.write_register(WHvX64RegisterRcx, ecx as u64)?;
        self.write_register(WHvX64RegisterRdx, edx as u64)?;
        Ok(())
    }

    /// Set MSR read result (value in EDX:EAX format).
    #[cfg(target_os = "windows")]
    pub fn set_msr_result(&self, value: u64) -> Result<()> {
        self.write_register(WHvX64RegisterRax, value & 0xFFFFFFFF)?;
        self.write_register(WHvX64RegisterRdx, value >> 32)?;
        Ok(())
    }

    /// Read a segment register (FS or GS) base address.
    #[cfg(target_os = "windows")]
    pub fn read_segment_base(&self, reg: WHV_REGISTER_NAME) -> Result<u64> {
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
            .map_err(|e| Error::VcpuError(format!("Failed to read segment register: {:?}", e)))?;

            Ok(reg_values[0].Segment.Base)
        }
    }

    /// Write a segment register base only (preserve other fields).
    #[cfg(target_os = "windows")]
    pub fn write_segment_base(&self, reg: WHV_REGISTER_NAME, base: u64) -> Result<()> {
        unsafe {
            // First read the current segment value
            let reg_names = [reg];
            let mut reg_values = [WHV_REGISTER_VALUE::default()];

            WHvGetVirtualProcessorRegisters(
                self.partition,
                self.index,
                reg_names.as_ptr(),
                1,
                reg_values.as_mut_ptr(),
            )
            .map_err(|e| Error::VcpuError(format!("Failed to read segment for base update: {:?}", e)))?;

            // Modify only the base
            reg_values[0].Segment.Base = base;

            // Write it back
            WHvSetVirtualProcessorRegisters(
                self.partition,
                self.index,
                reg_names.as_ptr(),
                1,
                reg_values.as_ptr(),
            )
            .map_err(|e| Error::VcpuError(format!("Failed to write segment base: {:?}", e)))?;

            Ok(())
        }
    }

    /// Handle MSR write for special MSRs that map to WHP registers.
    /// Returns true if the MSR was handled, false otherwise.
    #[cfg(target_os = "windows")]
    pub fn handle_msr_write(&self, msr: u32, value: u64) -> Result<bool> {
        // Map special MSRs to WHP register equivalents
        // These MUST be handled via WHvSetVirtualProcessorRegisters, not emulated
        match msr {
            0xC0000100 => {
                // IA32_FS_BASE -> Update FS segment's base field
                self.write_segment_base(WHvX64RegisterFs, value)?;
                Ok(true)
            }
            0xC0000101 => {
                // IA32_GS_BASE -> Update GS segment's base field
                self.write_segment_base(WHvX64RegisterGs, value)?;
                Ok(true)
            }
            0xC0000102 => {
                // IA32_KERNEL_GS_BASE -> WHvX64RegisterKernelGsBase
                self.write_register(WHvX64RegisterKernelGsBase, value)?;
                Ok(true)
            }
            0xC0000080 => {
                // IA32_EFER -> WHvX64RegisterEfer
                self.write_register(WHvX64RegisterEfer, value)?;
                Ok(true)
            }
            0xC0000081 => {
                // IA32_STAR -> WHvX64RegisterStar
                self.write_register(WHvX64RegisterStar, value)?;
                Ok(true)
            }
            0xC0000082 => {
                // IA32_LSTAR -> WHvX64RegisterLstar
                self.write_register(WHvX64RegisterLstar, value)?;
                Ok(true)
            }
            0xC0000083 => {
                // IA32_CSTAR -> WHvX64RegisterCstar
                self.write_register(WHvX64RegisterCstar, value)?;
                Ok(true)
            }
            0xC0000084 => {
                // IA32_FMASK -> WHvX64RegisterSfmask
                self.write_register(WHvX64RegisterSfmask, value)?;
                Ok(true)
            }
            _ => Ok(false), // Not a special MSR
        }
    }

    /// Handle MSR read for special MSRs that map to WHP registers.
    /// Returns Some(value) if the MSR was handled, None otherwise.
    #[cfg(target_os = "windows")]
    pub fn handle_msr_read(&self, msr: u32) -> Result<Option<u64>> {
        match msr {
            0xC0000100 => Ok(Some(self.read_segment_base(WHvX64RegisterFs)?)),
            0xC0000101 => Ok(Some(self.read_segment_base(WHvX64RegisterGs)?)),
            0xC0000102 => Ok(Some(self.read_register(WHvX64RegisterKernelGsBase)?)),
            0xC0000080 => Ok(Some(self.read_register(WHvX64RegisterEfer)?)),
            0xC0000081 => Ok(Some(self.read_register(WHvX64RegisterStar)?)),
            0xC0000082 => Ok(Some(self.read_register(WHvX64RegisterLstar)?)),
            0xC0000083 => Ok(Some(self.read_register(WHvX64RegisterCstar)?)),
            0xC0000084 => Ok(Some(self.read_register(WHvX64RegisterSfmask)?)),
            _ => Ok(None),
        }
    }

    /// Advance RIP by the given amount (used after handling exits).
    #[cfg(target_os = "windows")]
    pub fn advance_rip(&self, bytes: u64) -> Result<()> {
        let rip = self.read_register(WHvX64RegisterRip)?;
        self.write_register(WHvX64RegisterRip, rip + bytes)
    }

    // Non-Windows stubs
    #[cfg(not(target_os = "windows"))]
    pub fn read_register(&self, _reg: u32) -> Result<u64> {
        Err(Error::HypervisorNotAvailable)
    }

    #[cfg(not(target_os = "windows"))]
    pub fn write_register(&self, _reg: u32, _value: u64) -> Result<()> {
        Err(Error::HypervisorNotAvailable)
    }

    #[cfg(not(target_os = "windows"))]
    pub fn set_rax(&self, _value: u64) -> Result<()> {
        Err(Error::HypervisorNotAvailable)
    }

    #[cfg(not(target_os = "windows"))]
    pub fn get_rax(&self) -> Result<u64> {
        Err(Error::HypervisorNotAvailable)
    }

    #[cfg(not(target_os = "windows"))]
    pub fn set_cpuid_result(&self, _eax: u32, _ebx: u32, _ecx: u32, _edx: u32) -> Result<()> {
        Err(Error::HypervisorNotAvailable)
    }

    #[cfg(not(target_os = "windows"))]
    pub fn set_msr_result(&self, _value: u64) -> Result<()> {
        Err(Error::HypervisorNotAvailable)
    }

    #[cfg(not(target_os = "windows"))]
    pub fn advance_rip(&self, _bytes: u64) -> Result<()> {
        Err(Error::HypervisorNotAvailable)
    }

    #[cfg(not(target_os = "windows"))]
    pub fn init_long_mode(&self, _entry_point: u64, _boot_params_addr: u64) -> Result<()> {
        Err(Error::HypervisorNotAvailable)
    }

    #[cfg(not(target_os = "windows"))]
    pub fn init_real_mode(&self) -> Result<()> {
        Err(Error::HypervisorNotAvailable)
    }

    #[cfg(not(target_os = "windows"))]
    pub fn write_segment(&self, _reg: u32, _selector: u16, _base: u64, _limit: u32, _attributes: u16) -> Result<()> {
        Err(Error::HypervisorNotAvailable)
    }

    #[cfg(not(target_os = "windows"))]
    pub fn write_table_register(&self, _reg: u32, _base: u64, _limit: u16) -> Result<()> {
        Err(Error::HypervisorNotAvailable)
    }

    #[cfg(not(target_os = "windows"))]
    pub fn read_segment_base(&self, _reg: u32) -> Result<u64> {
        Err(Error::HypervisorNotAvailable)
    }

    #[cfg(not(target_os = "windows"))]
    pub fn write_segment_base(&self, _reg: u32, _base: u64) -> Result<()> {
        Err(Error::HypervisorNotAvailable)
    }

    #[cfg(not(target_os = "windows"))]
    pub fn handle_msr_write(&self, _msr: u32, _value: u64) -> Result<bool> {
        Err(Error::HypervisorNotAvailable)
    }

    #[cfg(not(target_os = "windows"))]
    pub fn handle_msr_read(&self, _msr: u32) -> Result<Option<u64>> {
        Err(Error::HypervisorNotAvailable)
    }
}
