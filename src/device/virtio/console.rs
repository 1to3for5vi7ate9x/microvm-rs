//! Virtio console device.
//!
//! TODO: Implement virtio-console for guest console I/O.

use crate::device::VirtioDevice;
use crate::error::Result;

/// Virtio console device.
pub struct VirtioConsole {
    /// Device features
    features: u64,
    /// Acknowledged features
    acked_features: u64,
}

impl VirtioConsole {
    /// Create a new virtio-console device.
    pub fn new() -> Self {
        Self {
            features: super::feature::VIRTIO_F_VERSION_1,
            acked_features: 0,
        }
    }
}

impl Default for VirtioConsole {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtioDevice for VirtioConsole {
    fn device_type(&self) -> u32 {
        crate::device::device_type::CONSOLE
    }

    fn features(&self) -> u64 {
        self.features
    }

    fn ack_features(&mut self, features: u64) {
        self.acked_features = features & self.features;
    }

    fn read_config(&self, _offset: u64, _data: &mut [u8]) {
        // Console config space is minimal
    }

    fn write_config(&mut self, _offset: u64, _data: &[u8]) {
        // Console config is read-only
    }

    fn activate(&mut self) -> Result<()> {
        // TODO: Set up virtqueues (rx, tx)
        Ok(())
    }

    fn reset(&mut self) {
        self.acked_features = 0;
    }
}
