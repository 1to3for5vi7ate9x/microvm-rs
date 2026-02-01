//! Windows Hypervisor Platform API bindings.
//!
//! These bindings wrap the WHP API from windows-rs.
//!
//! ## References
//!
//! - https://docs.microsoft.com/en-us/virtualization/api/hypervisor-platform/
//! - https://docs.microsoft.com/en-us/virtualization/api/hypervisor-platform/funcs/whvgetcapability

#![allow(dead_code)]

#[cfg(target_os = "windows")]
use windows::Win32::System::Hypervisor::*;

/// Check if WHP is available on this system.
#[cfg(target_os = "windows")]
pub fn check_whp_available() -> bool {
    unsafe {
        let mut capability = WHV_CAPABILITY::default();
        let result = WHvGetCapability(
            WHvCapabilityCodeHypervisorPresent,
            &mut capability as *mut _ as *mut _,
            std::mem::size_of::<WHV_CAPABILITY>() as u32,
            None,
        );

        if result.is_ok() {
            capability.HypervisorPresent.as_bool()
        } else {
            false
        }
    }
}

#[cfg(not(target_os = "windows"))]
pub fn check_whp_available() -> bool {
    false
}

// WHP return code helpers
#[cfg(target_os = "windows")]
pub type WhpResult = windows::core::Result<()>;

#[cfg(target_os = "windows")]
pub fn whp_result(result: windows::core::HRESULT) -> crate::error::Result<()> {
    if result.is_ok() {
        Ok(())
    } else {
        Err(crate::error::Error::WhpError(format!(
            "WHP error: 0x{:08X}",
            result.0
        )))
    }
}

// Exit reasons from Windows SDK (WinHvPlatformDefs.h)
// These are the actual hex values from the Windows API
#[cfg(target_os = "windows")]
pub mod exit_reason {
    pub const WHV_RUN_VP_EXIT_REASON_NONE: i32 = 0x0000;
    pub const WHV_RUN_VP_EXIT_REASON_MEMORY_ACCESS: i32 = 0x0001;
    pub const WHV_RUN_VP_EXIT_REASON_X64_IO_PORT_ACCESS: i32 = 0x0002;
    pub const WHV_RUN_VP_EXIT_REASON_EXCEPTION: i32 = 0x0003;  // Intercepted exception
    pub const WHV_RUN_VP_EXIT_REASON_UNRECOVERABLE_EXCEPTION: i32 = 0x0004;
    pub const WHV_RUN_VP_EXIT_REASON_INVALID_VP_REGISTER_VALUE: i32 = 0x0005;
    pub const WHV_RUN_VP_EXIT_REASON_UNSUPPORTED_FEATURE: i32 = 0x0006;
    pub const WHV_RUN_VP_EXIT_REASON_X64_INTERRUPTION_DELIVERABLE: i32 = 0x0007;
    pub const WHV_RUN_VP_EXIT_REASON_X64_HALT: i32 = 0x0008;
    pub const WHV_RUN_VP_EXIT_REASON_X64_APIC_EOI: i32 = 0x0009;
    pub const WHV_RUN_VP_EXIT_REASON_SYNIC_SINT_DELIVERABLE: i32 = 0x000A;
    pub const WHV_RUN_VP_EXIT_REASON_X64_CPUID: i32 = 0x1000;
    pub const WHV_RUN_VP_EXIT_REASON_X64_MSR_ACCESS: i32 = 0x1001;
    pub const WHV_RUN_VP_EXIT_REASON_X64_RDTSC: i32 = 0x1002;
    pub const WHV_RUN_VP_EXIT_REASON_X64_APIC_SMI: i32 = 0x1003;
    pub const WHV_RUN_VP_EXIT_REASON_HYPERCALL: i32 = 0x1004;
    pub const WHV_RUN_VP_EXIT_REASON_CANCELED: i32 = 0x2001;
}
