//! Virtual device emulation.
//!
//! This module provides virtio device implementations for guest I/O.

pub mod serial;
pub mod virtio;

#[cfg(target_arch = "aarch64")]
pub mod pl011;

#[cfg(target_arch = "aarch64")]
pub mod gic;

#[cfg(target_arch = "aarch64")]
pub use pl011::Pl011;

#[cfg(target_arch = "aarch64")]
pub use gic::Gic;

// Re-export commonly used virtio types
pub use virtio::{VirtioBlk, VirtioNet, VirtioMmioTransport, Queue};

use crate::error::Result;

/// Trait for virtio devices.
pub trait VirtioDevice: Send {
    /// Get the device type ID.
    fn device_type(&self) -> u32;

    /// Get the device features.
    fn features(&self) -> u64;

    /// Acknowledge features from the driver.
    fn ack_features(&mut self, features: u64);

    /// Read from device-specific configuration space.
    fn read_config(&self, offset: u64, data: &mut [u8]);

    /// Write to device-specific configuration space.
    fn write_config(&mut self, offset: u64, data: &[u8]);

    /// Activate the device.
    fn activate(&mut self) -> Result<()>;

    /// Reset the device.
    fn reset(&mut self);
}

/// Device type IDs (virtio spec).
pub mod device_type {
    pub const NET: u32 = 1;
    pub const BLOCK: u32 = 2;
    pub const CONSOLE: u32 = 3;
    pub const RNG: u32 = 4;
    pub const BALLOON: u32 = 5;
    pub const RPMSG: u32 = 7;
    pub const SCSI: u32 = 8;
    pub const P9: u32 = 9;
    pub const RPROC_SERIAL: u32 = 11;
    pub const CAIF: u32 = 12;
    pub const GPU: u32 = 16;
    pub const INPUT: u32 = 18;
    pub const VSOCK: u32 = 19;
    pub const CRYPTO: u32 = 20;
    pub const IOMMU: u32 = 23;
    pub const MEM: u32 = 24;
    pub const FS: u32 = 26;
    pub const PMEM: u32 = 27;
}
