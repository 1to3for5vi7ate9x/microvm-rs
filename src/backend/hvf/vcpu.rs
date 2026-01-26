//! HVF vCPU management.

use super::bindings::{self, hv_result};
use crate::error::{Error, Result};

/// Exit reason from vCPU execution.
#[derive(Debug, Clone)]
pub enum VcpuExit {
    /// I/O port read (x86)
    IoIn { port: u16, size: u8 },
    /// I/O port write (x86)
    IoOut { port: u16, data: Vec<u8> },
    /// Memory-mapped I/O read (includes syndrome for register extraction)
    MmioRead { addr: u64, size: u8, syndrome: u64 },
    /// Memory-mapped I/O write (includes syndrome for register extraction)
    MmioWrite { addr: u64, data: Vec<u8>, syndrome: u64 },
    /// Guest executed HLT instruction
    Hlt,
    /// Guest shutdown
    Shutdown,
    /// Virtual timer activated (ARM64)
    VTimer,
    /// HVC (Hypervisor Call) instruction executed
    Hvc { imm: u16 },
    /// SMC (Secure Monitor Call) instruction executed
    Smc { imm: u16 },
    /// WFI (Wait For Interrupt) instruction executed
    Wfi,
    /// System register access (MSR/MRS)
    SystemRegAccess { reg: u32, is_write: bool, rt: u8, syndrome: u64 },
    /// Breakpoint (BRK instruction)
    Breakpoint { imm: u16 },
    /// Unknown exception with EC and syndrome for debugging
    Exception { ec: u32, syndrome: u64 },
    /// Unknown exit reason
    Unknown(u32),
}

/// Represents an HVF virtual CPU.
pub struct Vcpu {
    /// vCPU ID
    id: u32,
    /// Whether this vCPU has been created
    created: bool,

    // ARM64 specific
    #[cfg(target_arch = "aarch64")]
    handle: bindings::hv_vcpu_t,
    #[cfg(target_arch = "aarch64")]
    exit_info: *mut bindings::hv_vcpu_exit_t,
}

// Safety: Vcpu is only accessed from a single thread (the vCPU thread).
// The exit_info pointer is allocated by HVF and is stable for the lifetime of the vCPU.
unsafe impl Send for Vcpu {}

impl Vcpu {
    /// Create a new vCPU.
    pub fn new(id: u32) -> Result<Self> {
        #[cfg(target_arch = "x86_64")]
        {
            let mut vcpu_id: bindings::hv_vcpuid_t = 0;
            let ret = unsafe {
                bindings::hv_vcpu_create(&mut vcpu_id, bindings::HV_VCPU_DEFAULT)
            };
            hv_result(ret).map_err(|_| {
                Error::VcpuError(format!(
                    "Failed to create vCPU: {}",
                    bindings::hv_return_string(ret)
                ))
            })?;

            // Initialize vCPU state
            let vcpu = Self {
                id: vcpu_id,
                created: true,
            };
            vcpu.init_x86()?;
            Ok(vcpu)
        }

        #[cfg(target_arch = "aarch64")]
        {
            let config = unsafe { bindings::hv_vcpu_config_create() };
            let mut handle: bindings::hv_vcpu_t = 0;
            let mut exit_info: *mut bindings::hv_vcpu_exit_t = std::ptr::null_mut();

            let ret = unsafe {
                bindings::hv_vcpu_create(&mut handle, &mut exit_info, config)
            };
            hv_result(ret).map_err(|_| {
                Error::VcpuError(format!(
                    "Failed to create vCPU: {}",
                    bindings::hv_return_string(ret)
                ))
            })?;

            let vcpu = Self {
                id,
                created: true,
                handle,
                exit_info,
            };
            vcpu.init_arm64()?;
            Ok(vcpu)
        }
    }

    /// Get the vCPU ID.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Get the vCPU handle (ARM64).
    #[cfg(target_arch = "aarch64")]
    pub fn handle(&self) -> bindings::hv_vcpu_t {
        self.handle
    }

    /// Initialize x86_64 vCPU state.
    #[cfg(target_arch = "x86_64")]
    fn init_x86(&self) -> Result<()> {
        use super::bindings::{vmcs, x86_reg};

        // Set up segment registers for real mode
        // CS: base=0, limit=0xFFFF, selector=0
        self.write_vmcs(vmcs::VMCS_GUEST_CS_SELECTOR, 0)?;
        self.write_vmcs(vmcs::VMCS_GUEST_CS_BASE, 0)?;
        self.write_vmcs(vmcs::VMCS_GUEST_CS_LIMIT, 0xFFFF)?;
        self.write_vmcs(vmcs::VMCS_GUEST_CS_AR, 0x9B)?; // Present, R/X, Accessed

        // Set up other segment registers
        for &selector in &[
            vmcs::VMCS_GUEST_SS_SELECTOR,
            vmcs::VMCS_GUEST_DS_SELECTOR,
            vmcs::VMCS_GUEST_ES_SELECTOR,
            vmcs::VMCS_GUEST_FS_SELECTOR,
            vmcs::VMCS_GUEST_GS_SELECTOR,
        ] {
            self.write_vmcs(selector, 0)?;
        }

        // Set up control registers
        self.write_register(x86_reg::HV_X86_CR0, 0x20)?; // NE bit
        self.write_register(x86_reg::HV_X86_CR4, 0)?;

        // Set RFLAGS (interrupts disabled, reserved bit 1 set)
        self.write_register(x86_reg::HV_X86_RFLAGS, 0x2)?;

        // Set RIP to 0 (will be updated when loading code)
        self.write_register(x86_reg::HV_X86_RIP, 0)?;

        Ok(())
    }

    /// Initialize ARM64 vCPU state.
    #[cfg(target_arch = "aarch64")]
    fn init_arm64(&self) -> Result<()> {
        use super::bindings::{arm64_reg, arm64_sys_reg};

        // Set PC to 0 (will be updated when loading code)
        self.write_register(arm64_reg::HV_REG_PC, 0)?;

        // Set CPSR (EL1h mode, interrupts masked at startup)
        // Bits: D=1 A=1 I=1 F=1 M=0b00101 (EL1h)
        self.write_register(arm64_reg::HV_REG_CPSR, 0x3C5)?;

        // Set SCTLR_EL1 to disable MMU, caches, alignment checks
        // Bit 0 (M) = 0: MMU disabled
        // Bit 2 (C) = 0: Data cache disabled
        // Bit 12 (I) = 0: Instruction cache disabled
        // All other bits = 0 for clean state
        self.write_sys_register(arm64_sys_reg::HV_SYS_REG_SCTLR_EL1, 0)?;

        // Unmask the vtimer so we get VM exits when it fires
        self.set_vtimer_mask(false)?;

        Ok(())
    }

    /// Read a register value.
    #[cfg(target_arch = "x86_64")]
    pub fn read_register(&self, reg: bindings::hv_x86_reg_t) -> Result<u64> {
        let mut value: u64 = 0;
        let ret = unsafe { bindings::hv_vcpu_read_register(self.id, reg, &mut value) };
        hv_result(ret)?;
        Ok(value)
    }

    /// Write a register value.
    #[cfg(target_arch = "x86_64")]
    pub fn write_register(&self, reg: bindings::hv_x86_reg_t, value: u64) -> Result<()> {
        let ret = unsafe { bindings::hv_vcpu_write_register(self.id, reg, value) };
        hv_result(ret)
    }

    /// Read a VMCS field.
    #[cfg(target_arch = "x86_64")]
    pub fn read_vmcs(&self, field: u32) -> Result<u64> {
        let mut value: u64 = 0;
        let ret = unsafe { bindings::hv_vmx_vcpu_read_vmcs(self.id, field, &mut value) };
        hv_result(ret)?;
        Ok(value)
    }

    /// Write a VMCS field.
    #[cfg(target_arch = "x86_64")]
    pub fn write_vmcs(&self, field: u32, value: u64) -> Result<()> {
        let ret = unsafe { bindings::hv_vmx_vcpu_write_vmcs(self.id, field, value) };
        hv_result(ret)
    }

    /// Read a register value (ARM64).
    #[cfg(target_arch = "aarch64")]
    pub fn read_register(&self, reg: bindings::hv_reg_t) -> Result<u64> {
        let mut value: u64 = 0;
        let ret = unsafe { bindings::hv_vcpu_get_reg(self.handle, reg, &mut value) };
        hv_result(ret)?;
        Ok(value)
    }

    /// Write a register value (ARM64).
    #[cfg(target_arch = "aarch64")]
    pub fn write_register(&self, reg: bindings::hv_reg_t, value: u64) -> Result<()> {
        let ret = unsafe { bindings::hv_vcpu_set_reg(self.handle, reg, value) };
        hv_result(ret)
    }

    /// Set vtimer mask (ARM64).
    #[cfg(target_arch = "aarch64")]
    pub fn set_vtimer_mask(&self, masked: bool) -> Result<()> {
        let ret = unsafe { bindings::hv_vcpu_set_vtimer_mask(self.handle, masked) };
        hv_result(ret)
    }

    /// Set pending interrupt (ARM64).
    #[cfg(target_arch = "aarch64")]
    pub fn set_pending_interrupt(&self, interrupt_type: bindings::hv_interrupt_type_t, pending: bool) -> Result<()> {
        let ret = unsafe { bindings::hv_vcpu_set_pending_interrupt(self.handle, interrupt_type, pending) };
        hv_result(ret)
    }

    /// Get a handle for forcing vCPU exit from another thread.
    #[cfg(target_arch = "aarch64")]
    pub fn get_exit_handle(&self) -> VcpuExitHandle {
        VcpuExitHandle { handle: self.handle }
    }

    /// Force the vCPU to exit from hv_vcpu_run().
    /// This can be called from another thread to interrupt a blocking run.
    #[cfg(target_arch = "aarch64")]
    pub fn force_exit(&self) -> Result<()> {
        let ret = unsafe { bindings::hv_vcpus_exit(&self.handle as *const _, 1) };
        hv_result(ret)
    }

    /// Read a system register value (ARM64).
    #[cfg(target_arch = "aarch64")]
    pub fn read_sys_register(&self, reg: bindings::hv_sys_reg_t) -> Result<u64> {
        let mut value: u64 = 0;
        let ret = unsafe { bindings::hv_vcpu_get_sys_reg(self.handle, reg, &mut value) };
        hv_result(ret)?;
        Ok(value)
    }

    /// Write a system register value (ARM64).
    #[cfg(target_arch = "aarch64")]
    pub fn write_sys_register(&self, reg: bindings::hv_sys_reg_t, value: u64) -> Result<()> {
        let ret = unsafe { bindings::hv_vcpu_set_sys_reg(self.handle, reg, value) };
        hv_result(ret)
    }

    /// Run the vCPU until an exit occurs.
    pub fn run(&mut self) -> Result<VcpuExit> {
        #[cfg(target_arch = "x86_64")]
        {
            let ret = unsafe { bindings::hv_vcpu_run(self.id) };
            hv_result(ret)?;

            // Read exit reason from VMCS
            let exit_reason = self.read_vmcs(bindings::vmcs::VMCS_RO_EXIT_REASON)? as u32;
            self.handle_exit_x86(exit_reason)
        }

        #[cfg(target_arch = "aarch64")]
        {
            let ret = unsafe { bindings::hv_vcpu_run(self.handle) };
            hv_result(ret)?;

            // Read exit reason from exit info
            let exit_reason = unsafe { (*self.exit_info).reason };
            self.handle_exit_arm64(exit_reason)
        }
    }

    /// Handle x86_64 VM exit.
    #[cfg(target_arch = "x86_64")]
    fn handle_exit_x86(&self, exit_reason: u32) -> Result<VcpuExit> {
        // VMX exit reasons
        const VMX_EXIT_HLT: u32 = 12;
        const VMX_EXIT_IO: u32 = 30;
        const VMX_EXIT_EPT_VIOLATION: u32 = 48;

        match exit_reason {
            VMX_EXIT_HLT => Ok(VcpuExit::Hlt),
            VMX_EXIT_IO => {
                let qualification = self.read_vmcs(bindings::vmcs::VMCS_RO_EXIT_QUALIFIC)?;
                let port = ((qualification >> 16) & 0xFFFF) as u16;
                let size = ((qualification & 0x7) + 1) as u8;
                let is_out = (qualification & 0x8) == 0;

                if is_out {
                    // Read data from RAX
                    let rax = self.read_register(bindings::x86_reg::HV_X86_RAX)?;
                    let data = rax.to_le_bytes()[..size as usize].to_vec();
                    Ok(VcpuExit::IoOut { port, data })
                } else {
                    Ok(VcpuExit::IoIn { port, size })
                }
            }
            VMX_EXIT_EPT_VIOLATION => {
                let gpa = self.read_vmcs(bindings::vmcs::VMCS_RO_GUEST_LIN_ADDR)?;
                let qualification = self.read_vmcs(bindings::vmcs::VMCS_RO_EXIT_QUALIFIC)?;
                let is_write = (qualification & 0x2) != 0;

                if is_write {
                    Ok(VcpuExit::MmioWrite {
                        addr: gpa,
                        data: vec![],  // TODO: Read actual data
                        syndrome: 0,   // Not used on x86
                    })
                } else {
                    Ok(VcpuExit::MmioRead {
                        addr: gpa,
                        size: 4,  // TODO: Determine actual size
                        syndrome: 0,   // Not used on x86
                    })
                }
            }
            _ => Ok(VcpuExit::Unknown(exit_reason)),
        }
    }

    /// Handle ARM64 VM exit.
    #[cfg(target_arch = "aarch64")]
    fn handle_exit_arm64(&self, exit_reason: u32) -> Result<VcpuExit> {
        use super::bindings::arm64_exit;

        // Exception Class (EC) values for ARM64
        const EC_UNKNOWN: u32 = 0x00;  // Unknown reason
        const EC_WFI_WFE: u32 = 0x01;  // WFI/WFE trapped
        const EC_SVC64: u32 = 0x15;    // SVC instruction in AArch64
        const EC_HVC64: u32 = 0x16;    // HVC instruction in AArch64
        const EC_SMC64: u32 = 0x17;    // SMC instruction in AArch64
        const EC_MSR_MRS: u32 = 0x18;  // MSR/MRS/System register access
        const EC_IABT_LOW: u32 = 0x20; // Instruction abort from lower EL
        const EC_IABT_CUR: u32 = 0x21; // Instruction abort from current EL
        const EC_PC_ALIGN: u32 = 0x22; // PC alignment fault
        const EC_DABT_LOW: u32 = 0x24; // Data abort from lower EL
        const EC_DABT_CUR: u32 = 0x25; // Data abort from current EL
        const EC_SP_ALIGN: u32 = 0x26; // SP alignment fault
        const EC_BRK: u32 = 0x3C;      // BRK instruction (breakpoint)

        match exit_reason {
            arm64_exit::HV_EXIT_REASON_CANCELED => Ok(VcpuExit::Shutdown),
            arm64_exit::HV_EXIT_REASON_EXCEPTION => {
                // Parse exception syndrome
                let syndrome = unsafe { (*self.exit_info).exception.syndrome };
                let ec = ((syndrome >> 26) & 0x3F) as u32;

                match ec {
                    EC_UNKNOWN | EC_WFI_WFE => {
                        // WFI/WFE instruction - just report it
                        Ok(VcpuExit::Wfi)
                    }
                    EC_HVC64 => {
                        // HVC instruction - extract immediate value from ISS (bits 15:0)
                        let imm = (syndrome & 0xFFFF) as u16;
                        Ok(VcpuExit::Hvc { imm })
                    }
                    EC_SMC64 => {
                        // SMC instruction - extract immediate value from ISS (bits 15:0)
                        let imm = (syndrome & 0xFFFF) as u16;
                        Ok(VcpuExit::Smc { imm })
                    }
                    EC_MSR_MRS => {
                        // MSR/MRS system register access
                        // ISS encoding: Op0[21:20], Op2[19:17], Op1[16:14], CRn[13:10], Rt[9:5], CRm[4:1], Dir[0]
                        let is_write = (syndrome & 1) == 0; // Direction: 0=write, 1=read
                        let rt = ((syndrome >> 5) & 0x1F) as u8;
                        let reg = ((syndrome >> 1) & 0xFFFFF) as u32; // System register encoding
                        Ok(VcpuExit::SystemRegAccess { reg, is_write, rt, syndrome })
                    }
                    EC_BRK => {
                        // BRK instruction (breakpoint)
                        let imm = (syndrome & 0xFFFF) as u16;
                        Ok(VcpuExit::Breakpoint { imm })
                    }
                    EC_DABT_LOW | EC_DABT_CUR => {
                        // Data abort (MMIO access)
                        let addr = unsafe { (*self.exit_info).exception.physical_address };
                        let is_write = (syndrome & 0x40) != 0;

                        // Extract access size from SAS (bits 23:22)
                        let sas = ((syndrome >> 22) & 0x3) as u8;
                        let size = 1u8 << sas; // 1, 2, 4, or 8 bytes

                        if is_write {
                            Ok(VcpuExit::MmioWrite { addr, data: vec![], syndrome })
                        } else {
                            Ok(VcpuExit::MmioRead { addr, size, syndrome })
                        }
                    }
                    _ => {
                        // Unknown exception class - return with EC for debugging
                        Ok(VcpuExit::Exception { ec, syndrome })
                    }
                }
            }
            arm64_exit::HV_EXIT_REASON_VTIMER_ACTIVATED => {
                // Timer interrupt - inject IRQ and unmask
                Ok(VcpuExit::VTimer)
            }
            _ => Ok(VcpuExit::Unknown(exit_reason)),
        }
    }
}

impl Drop for Vcpu {
    fn drop(&mut self) {
        if self.created {
            #[cfg(target_arch = "x86_64")]
            unsafe {
                bindings::hv_vcpu_destroy(self.id);
            }

            #[cfg(target_arch = "aarch64")]
            unsafe {
                bindings::hv_vcpu_destroy(self.handle);
            }
        }
    }
}

/// Handle for forcing vCPU exit from another thread.
/// This is safe to send between threads as it only contains
/// the vCPU handle which is stable for the lifetime of the vCPU.
#[cfg(target_arch = "aarch64")]
#[derive(Clone, Copy)]
pub struct VcpuExitHandle {
    handle: bindings::hv_vcpu_t,
}

#[cfg(target_arch = "aarch64")]
unsafe impl Send for VcpuExitHandle {}
#[cfg(target_arch = "aarch64")]
unsafe impl Sync for VcpuExitHandle {}

#[cfg(target_arch = "aarch64")]
impl VcpuExitHandle {
    /// Force the vCPU to exit from hv_vcpu_run().
    /// Can be called from any thread to interrupt a blocking run.
    pub fn force_exit(&self) -> Result<()> {
        let ret = unsafe { bindings::hv_vcpus_exit(&self.handle as *const _, 1) };
        hv_result(ret)
    }
}
