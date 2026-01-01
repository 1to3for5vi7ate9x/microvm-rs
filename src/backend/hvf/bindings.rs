//! Raw FFI bindings to Hypervisor.framework.
//!
//! These are low-level bindings to Apple's Hypervisor.framework.
//! Prefer using the higher-level wrappers in `vm.rs`, `vcpu.rs`, etc.
//!
//! ## References
//!
//! - https://developer.apple.com/documentation/hypervisor

#![allow(non_camel_case_types)]
#![allow(dead_code)]

use std::ffi::c_void;

// Link against Hypervisor.framework
#[link(name = "Hypervisor", kind = "framework")]
extern "C" {
    // VM Management
    pub fn hv_vm_create(flags: hv_vm_options_t) -> hv_return_t;
    pub fn hv_vm_destroy() -> hv_return_t;
    pub fn hv_vm_map(
        uva: *mut c_void,
        gpa: hv_gpaddr_t,
        size: usize,
        flags: hv_memory_flags_t,
    ) -> hv_return_t;
    pub fn hv_vm_unmap(gpa: hv_gpaddr_t, size: usize) -> hv_return_t;
    pub fn hv_vm_protect(
        gpa: hv_gpaddr_t,
        size: usize,
        flags: hv_memory_flags_t,
    ) -> hv_return_t;

    // vCPU Management (x86_64)
    #[cfg(target_arch = "x86_64")]
    pub fn hv_vcpu_create(vcpu: *mut hv_vcpuid_t, flags: hv_vcpu_options_t) -> hv_return_t;

    #[cfg(target_arch = "x86_64")]
    pub fn hv_vcpu_destroy(vcpu: hv_vcpuid_t) -> hv_return_t;

    #[cfg(target_arch = "x86_64")]
    pub fn hv_vcpu_run(vcpu: hv_vcpuid_t) -> hv_return_t;

    #[cfg(target_arch = "x86_64")]
    pub fn hv_vcpu_run_until(vcpu: hv_vcpuid_t, deadline: u64) -> hv_return_t;

    #[cfg(target_arch = "x86_64")]
    pub fn hv_vcpu_interrupt(vcpus: *const hv_vcpuid_t, count: u32) -> hv_return_t;

    #[cfg(target_arch = "x86_64")]
    pub fn hv_vcpu_read_register(
        vcpu: hv_vcpuid_t,
        reg: hv_x86_reg_t,
        value: *mut u64,
    ) -> hv_return_t;

    #[cfg(target_arch = "x86_64")]
    pub fn hv_vcpu_write_register(
        vcpu: hv_vcpuid_t,
        reg: hv_x86_reg_t,
        value: u64,
    ) -> hv_return_t;

    #[cfg(target_arch = "x86_64")]
    pub fn hv_vcpu_read_fpstate(
        vcpu: hv_vcpuid_t,
        buffer: *mut c_void,
        size: usize,
    ) -> hv_return_t;

    #[cfg(target_arch = "x86_64")]
    pub fn hv_vcpu_write_fpstate(
        vcpu: hv_vcpuid_t,
        buffer: *const c_void,
        size: usize,
    ) -> hv_return_t;

    #[cfg(target_arch = "x86_64")]
    pub fn hv_vcpu_enable_native_msr(vcpu: hv_vcpuid_t, msr: u32, enable: bool) -> hv_return_t;

    #[cfg(target_arch = "x86_64")]
    pub fn hv_vcpu_read_msr(vcpu: hv_vcpuid_t, msr: u32, value: *mut u64) -> hv_return_t;

    #[cfg(target_arch = "x86_64")]
    pub fn hv_vcpu_write_msr(vcpu: hv_vcpuid_t, msr: u32, value: u64) -> hv_return_t;

    #[cfg(target_arch = "x86_64")]
    pub fn hv_vcpu_invalidate_tlb(vcpu: hv_vcpuid_t) -> hv_return_t;

    #[cfg(target_arch = "x86_64")]
    pub fn hv_vcpu_flush(vcpu: hv_vcpuid_t) -> hv_return_t;

    #[cfg(target_arch = "x86_64")]
    pub fn hv_vcpu_set_space(vcpu: hv_vcpuid_t, asid: hv_vm_space_t) -> hv_return_t;

    // VMCS access (x86_64)
    #[cfg(target_arch = "x86_64")]
    pub fn hv_vmx_read_capability(
        field: hv_vmx_capability_t,
        value: *mut u64,
    ) -> hv_return_t;

    #[cfg(target_arch = "x86_64")]
    pub fn hv_vmx_vcpu_read_vmcs(
        vcpu: hv_vcpuid_t,
        field: u32,
        value: *mut u64,
    ) -> hv_return_t;

    #[cfg(target_arch = "x86_64")]
    pub fn hv_vmx_vcpu_write_vmcs(
        vcpu: hv_vcpuid_t,
        field: u32,
        value: u64,
    ) -> hv_return_t;

    // vCPU Management (ARM64)
    #[cfg(target_arch = "aarch64")]
    pub fn hv_vcpu_create(
        vcpu: *mut hv_vcpu_t,
        exit: *mut *mut hv_vcpu_exit_t,
        config: hv_vcpu_config_t,
    ) -> hv_return_t;

    #[cfg(target_arch = "aarch64")]
    pub fn hv_vcpu_destroy(vcpu: hv_vcpu_t) -> hv_return_t;

    #[cfg(target_arch = "aarch64")]
    pub fn hv_vcpu_run(vcpu: hv_vcpu_t) -> hv_return_t;

    #[cfg(target_arch = "aarch64")]
    pub fn hv_vcpus_exit(vcpus: *const hv_vcpu_t, count: u32) -> hv_return_t;

    #[cfg(target_arch = "aarch64")]
    pub fn hv_vcpu_get_reg(vcpu: hv_vcpu_t, reg: hv_reg_t, value: *mut u64) -> hv_return_t;

    #[cfg(target_arch = "aarch64")]
    pub fn hv_vcpu_set_reg(vcpu: hv_vcpu_t, reg: hv_reg_t, value: u64) -> hv_return_t;

    #[cfg(target_arch = "aarch64")]
    pub fn hv_vcpu_get_sys_reg(
        vcpu: hv_vcpu_t,
        reg: hv_sys_reg_t,
        value: *mut u64,
    ) -> hv_return_t;

    #[cfg(target_arch = "aarch64")]
    pub fn hv_vcpu_set_sys_reg(
        vcpu: hv_vcpu_t,
        reg: hv_sys_reg_t,
        value: u64,
    ) -> hv_return_t;

    #[cfg(target_arch = "aarch64")]
    pub fn hv_vcpu_get_pending_interrupt(
        vcpu: hv_vcpu_t,
        interrupt_type: hv_interrupt_type_t,
        pending: *mut bool,
    ) -> hv_return_t;

    #[cfg(target_arch = "aarch64")]
    pub fn hv_vcpu_set_pending_interrupt(
        vcpu: hv_vcpu_t,
        interrupt_type: hv_interrupt_type_t,
        pending: bool,
    ) -> hv_return_t;

    // vCPU configuration (ARM64)
    #[cfg(target_arch = "aarch64")]
    pub fn hv_vcpu_config_create() -> hv_vcpu_config_t;

    #[cfg(target_arch = "aarch64")]
    pub fn hv_vcpu_config_get_feature_reg(
        config: hv_vcpu_config_t,
        feature_reg: hv_feature_reg_t,
        value: *mut u64,
    ) -> hv_return_t;
}

// Basic types
pub type hv_return_t = i32;
pub type hv_gpaddr_t = u64;
pub type hv_vm_options_t = u64;
pub type hv_memory_flags_t = u64;
pub type hv_vm_space_t = u32;

// x86_64 specific types
#[cfg(target_arch = "x86_64")]
pub type hv_vcpuid_t = u32;
#[cfg(target_arch = "x86_64")]
pub type hv_vcpu_options_t = u64;
#[cfg(target_arch = "x86_64")]
pub type hv_x86_reg_t = u32;
#[cfg(target_arch = "x86_64")]
pub type hv_vmx_capability_t = u32;

// ARM64 specific types
#[cfg(target_arch = "aarch64")]
pub type hv_vcpu_t = u64;
#[cfg(target_arch = "aarch64")]
pub type hv_vcpu_config_t = *mut c_void;
#[cfg(target_arch = "aarch64")]
pub type hv_reg_t = u32;
#[cfg(target_arch = "aarch64")]
pub type hv_sys_reg_t = u16;
#[cfg(target_arch = "aarch64")]
pub type hv_feature_reg_t = u32;
#[cfg(target_arch = "aarch64")]
pub type hv_interrupt_type_t = u32;

// ARM64 exit info
#[cfg(target_arch = "aarch64")]
#[repr(C)]
pub struct hv_vcpu_exit_t {
    pub reason: hv_exit_reason_t,
    pub exception: hv_vcpu_exit_exception_t,
}

#[cfg(target_arch = "aarch64")]
pub type hv_exit_reason_t = u32;

#[cfg(target_arch = "aarch64")]
#[repr(C)]
pub struct hv_vcpu_exit_exception_t {
    pub syndrome: u64,
    pub virtual_address: u64,
    pub physical_address: u64,
}

// Return codes
pub const HV_SUCCESS: hv_return_t = 0;
pub const HV_ERROR: hv_return_t = 0xfae94001_u32 as i32;
pub const HV_BUSY: hv_return_t = 0xfae94002_u32 as i32;
pub const HV_BAD_ARGUMENT: hv_return_t = 0xfae94003_u32 as i32;
pub const HV_NO_RESOURCES: hv_return_t = 0xfae94005_u32 as i32;
pub const HV_NO_DEVICE: hv_return_t = 0xfae94006_u32 as i32;
pub const HV_DENIED: hv_return_t = 0xfae94007_u32 as i32;
pub const HV_UNSUPPORTED: hv_return_t = 0xfae9400f_u32 as i32;

// VM options
pub const HV_VM_DEFAULT: hv_vm_options_t = 0;

// vCPU options
#[cfg(target_arch = "x86_64")]
pub const HV_VCPU_DEFAULT: hv_vcpu_options_t = 0;

// Memory flags
pub const HV_MEMORY_READ: hv_memory_flags_t = 1 << 0;
pub const HV_MEMORY_WRITE: hv_memory_flags_t = 1 << 1;
pub const HV_MEMORY_EXEC: hv_memory_flags_t = 1 << 2;

// x86_64 registers
#[cfg(target_arch = "x86_64")]
pub mod x86_reg {
    use super::hv_x86_reg_t;

    pub const HV_X86_RIP: hv_x86_reg_t = 0;
    pub const HV_X86_RFLAGS: hv_x86_reg_t = 1;
    pub const HV_X86_RAX: hv_x86_reg_t = 2;
    pub const HV_X86_RCX: hv_x86_reg_t = 3;
    pub const HV_X86_RDX: hv_x86_reg_t = 4;
    pub const HV_X86_RBX: hv_x86_reg_t = 5;
    pub const HV_X86_RSI: hv_x86_reg_t = 6;
    pub const HV_X86_RDI: hv_x86_reg_t = 7;
    pub const HV_X86_RSP: hv_x86_reg_t = 8;
    pub const HV_X86_RBP: hv_x86_reg_t = 9;
    pub const HV_X86_R8: hv_x86_reg_t = 10;
    pub const HV_X86_R9: hv_x86_reg_t = 11;
    pub const HV_X86_R10: hv_x86_reg_t = 12;
    pub const HV_X86_R11: hv_x86_reg_t = 13;
    pub const HV_X86_R12: hv_x86_reg_t = 14;
    pub const HV_X86_R13: hv_x86_reg_t = 15;
    pub const HV_X86_R14: hv_x86_reg_t = 16;
    pub const HV_X86_R15: hv_x86_reg_t = 17;
    pub const HV_X86_CS: hv_x86_reg_t = 18;
    pub const HV_X86_SS: hv_x86_reg_t = 19;
    pub const HV_X86_DS: hv_x86_reg_t = 20;
    pub const HV_X86_ES: hv_x86_reg_t = 21;
    pub const HV_X86_FS: hv_x86_reg_t = 22;
    pub const HV_X86_GS: hv_x86_reg_t = 23;
    pub const HV_X86_IDT_BASE: hv_x86_reg_t = 24;
    pub const HV_X86_IDT_LIMIT: hv_x86_reg_t = 25;
    pub const HV_X86_GDT_BASE: hv_x86_reg_t = 26;
    pub const HV_X86_GDT_LIMIT: hv_x86_reg_t = 27;
    pub const HV_X86_LDTR: hv_x86_reg_t = 28;
    pub const HV_X86_LDT_BASE: hv_x86_reg_t = 29;
    pub const HV_X86_LDT_LIMIT: hv_x86_reg_t = 30;
    pub const HV_X86_LDT_AR: hv_x86_reg_t = 31;
    pub const HV_X86_TR: hv_x86_reg_t = 32;
    pub const HV_X86_TSS_BASE: hv_x86_reg_t = 33;
    pub const HV_X86_TSS_LIMIT: hv_x86_reg_t = 34;
    pub const HV_X86_TSS_AR: hv_x86_reg_t = 35;
    pub const HV_X86_CR0: hv_x86_reg_t = 36;
    pub const HV_X86_CR1: hv_x86_reg_t = 37;
    pub const HV_X86_CR2: hv_x86_reg_t = 38;
    pub const HV_X86_CR3: hv_x86_reg_t = 39;
    pub const HV_X86_CR4: hv_x86_reg_t = 40;
    pub const HV_X86_DR0: hv_x86_reg_t = 41;
    pub const HV_X86_DR1: hv_x86_reg_t = 42;
    pub const HV_X86_DR2: hv_x86_reg_t = 43;
    pub const HV_X86_DR3: hv_x86_reg_t = 44;
    pub const HV_X86_DR4: hv_x86_reg_t = 45;
    pub const HV_X86_DR5: hv_x86_reg_t = 46;
    pub const HV_X86_DR6: hv_x86_reg_t = 47;
    pub const HV_X86_DR7: hv_x86_reg_t = 48;
    pub const HV_X86_TPR: hv_x86_reg_t = 49;
    pub const HV_X86_XCR0: hv_x86_reg_t = 50;
}

// x86_64 VMCS fields
#[cfg(target_arch = "x86_64")]
pub mod vmcs {
    // Control fields
    pub const VMCS_CTRL_PIN_BASED: u32 = 0x00004000;
    pub const VMCS_CTRL_CPU_BASED: u32 = 0x00004002;
    pub const VMCS_CTRL_CPU_BASED2: u32 = 0x0000401E;
    pub const VMCS_CTRL_VMENTRY_CONTROLS: u32 = 0x00004012;
    pub const VMCS_CTRL_VMEXIT_CONTROLS: u32 = 0x0000400C;
    pub const VMCS_CTRL_EXC_BITMAP: u32 = 0x00004004;
    pub const VMCS_CTRL_CR0_MASK: u32 = 0x00006000;
    pub const VMCS_CTRL_CR0_SHADOW: u32 = 0x00006004;
    pub const VMCS_CTRL_CR4_MASK: u32 = 0x00006002;
    pub const VMCS_CTRL_CR4_SHADOW: u32 = 0x00006006;

    // Guest state
    pub const VMCS_GUEST_CS_SELECTOR: u32 = 0x00000802;
    pub const VMCS_GUEST_CS_BASE: u32 = 0x00006808;
    pub const VMCS_GUEST_CS_LIMIT: u32 = 0x00004802;
    pub const VMCS_GUEST_CS_AR: u32 = 0x00004816;
    pub const VMCS_GUEST_SS_SELECTOR: u32 = 0x00000804;
    pub const VMCS_GUEST_DS_SELECTOR: u32 = 0x00000806;
    pub const VMCS_GUEST_ES_SELECTOR: u32 = 0x00000800;
    pub const VMCS_GUEST_FS_SELECTOR: u32 = 0x00000808;
    pub const VMCS_GUEST_GS_SELECTOR: u32 = 0x0000080A;
    pub const VMCS_GUEST_TR_SELECTOR: u32 = 0x0000080E;
    pub const VMCS_GUEST_LDTR_SELECTOR: u32 = 0x0000080C;

    // Exit info
    pub const VMCS_RO_EXIT_REASON: u32 = 0x00004402;
    pub const VMCS_RO_EXIT_QUALIFIC: u32 = 0x00006400;
    pub const VMCS_RO_INSTR_LEN: u32 = 0x0000440C;
    pub const VMCS_RO_GUEST_LIN_ADDR: u32 = 0x0000640A;
}

// ARM64 registers
#[cfg(target_arch = "aarch64")]
pub mod arm64_reg {
    use super::hv_reg_t;

    pub const HV_REG_X0: hv_reg_t = 0;
    pub const HV_REG_X1: hv_reg_t = 1;
    pub const HV_REG_X2: hv_reg_t = 2;
    pub const HV_REG_X3: hv_reg_t = 3;
    pub const HV_REG_X29: hv_reg_t = 29; // FP
    pub const HV_REG_X30: hv_reg_t = 30; // LR
    pub const HV_REG_PC: hv_reg_t = 31;
    pub const HV_REG_FPCR: hv_reg_t = 32;
    pub const HV_REG_FPSR: hv_reg_t = 33;
    pub const HV_REG_CPSR: hv_reg_t = 34;
}

// ARM64 system registers
#[cfg(target_arch = "aarch64")]
pub mod arm64_sys_reg {
    use super::hv_sys_reg_t;

    pub const HV_SYS_REG_SPSR_EL1: hv_sys_reg_t = 0xC200;
    pub const HV_SYS_REG_SP_EL0: hv_sys_reg_t = 0xC208;
    pub const HV_SYS_REG_SP_EL1: hv_sys_reg_t = 0xE208;
    pub const HV_SYS_REG_ELR_EL1: hv_sys_reg_t = 0xE201;
    pub const HV_SYS_REG_SCTLR_EL1: hv_sys_reg_t = 0xC080;
    pub const HV_SYS_REG_TTBR0_EL1: hv_sys_reg_t = 0xC100;
    pub const HV_SYS_REG_TTBR1_EL1: hv_sys_reg_t = 0xC101;
    pub const HV_SYS_REG_TCR_EL1: hv_sys_reg_t = 0xC102;
    pub const HV_SYS_REG_MAIR_EL1: hv_sys_reg_t = 0xC510;
    pub const HV_SYS_REG_VBAR_EL1: hv_sys_reg_t = 0xC600;
}

// ARM64 exit reasons
#[cfg(target_arch = "aarch64")]
pub mod arm64_exit {
    use super::hv_exit_reason_t;

    pub const HV_EXIT_REASON_CANCELED: hv_exit_reason_t = 0;
    pub const HV_EXIT_REASON_EXCEPTION: hv_exit_reason_t = 1;
    pub const HV_EXIT_REASON_VTIMER_ACTIVATED: hv_exit_reason_t = 2;
    pub const HV_EXIT_REASON_UNKNOWN: hv_exit_reason_t = 3;
}

// ARM64 interrupt types
#[cfg(target_arch = "aarch64")]
pub mod arm64_interrupt {
    use super::hv_interrupt_type_t;

    pub const HV_INTERRUPT_TYPE_IRQ: hv_interrupt_type_t = 0;
    pub const HV_INTERRUPT_TYPE_FIQ: hv_interrupt_type_t = 1;
}

/// Convert HVF return code to a human-readable string.
pub fn hv_return_string(code: hv_return_t) -> &'static str {
    match code {
        HV_SUCCESS => "Success",
        HV_ERROR => "Error",
        HV_BUSY => "Busy",
        HV_BAD_ARGUMENT => "Bad argument",
        HV_NO_RESOURCES => "No resources",
        HV_NO_DEVICE => "No device",
        HV_DENIED => "Denied (missing entitlement?)",
        HV_UNSUPPORTED => "Unsupported",
        _ => "Unknown error",
    }
}

/// Check if an HVF return code indicates success.
#[inline]
pub fn hv_succeeded(code: hv_return_t) -> bool {
    code == HV_SUCCESS
}

/// Convert an HVF return code to a Result.
pub fn hv_result(code: hv_return_t) -> crate::error::Result<()> {
    if hv_succeeded(code) {
        Ok(())
    } else {
        Err(crate::error::Error::HvfError(code))
    }
}
