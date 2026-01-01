//! Kernel and boot loader functionality.
//!
//! This module handles loading Linux kernels and setting up boot parameters.

pub mod linux;

#[cfg(target_arch = "aarch64")]
pub mod arm64;

#[cfg(target_arch = "x86_64")]
pub mod x86_64;

pub use linux::LinuxLoader;
