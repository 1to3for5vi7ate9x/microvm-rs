//! Memory management for guest VMs.
//!
//! This module provides abstractions for guest physical memory
//! that work across all platform backends.

mod guest;

pub use guest::GuestMemoryRegion;

/// Standard memory layout for x86_64 guests.
pub mod layout {
    /// Real mode IVT and BDA (0 - 4KB)
    pub const REAL_MODE_IVT_BEGIN: u64 = 0x0000;

    /// Boot parameters (4KB - 40KB)
    pub const BOOT_PARAMS_START: u64 = 0x1000;

    /// Kernel command line
    pub const CMDLINE_START: u64 = 0x20000;
    pub const CMDLINE_MAX_SIZE: u64 = 0x10000;

    /// Legacy VGA memory hole (640KB - 1MB)
    pub const VGA_HOLE_START: u64 = 0xA0000;
    pub const VGA_HOLE_END: u64 = 0x100000;

    /// Kernel load address (1MB)
    pub const KERNEL_START: u64 = 0x100000;

    /// Initrd is loaded after kernel
    /// Actual address depends on kernel size

    /// High memory starts at 4GB
    pub const HIGH_MEMORY_START: u64 = 0x1_0000_0000;
}
