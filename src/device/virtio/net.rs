//! Virtio network device.
//!
//! TODO: Implement virtio-net for guest networking.

use crate::device::VirtioDevice;
use crate::error::Result;

/// Virtio network device.
pub struct VirtioNet {
    /// MAC address
    mac: [u8; 6],
    /// Device features
    features: u64,
    /// Acknowledged features
    acked_features: u64,
}

impl VirtioNet {
    /// Create a new virtio-net device with a random MAC address.
    pub fn new() -> Self {
        // Generate a random locally-administered MAC address
        let mut mac = [0u8; 6];
        mac[0] = 0x52; // Locally administered, unicast
        mac[1] = 0x54;
        mac[2] = 0x00;
        // Random last 3 bytes
        mac[3] = rand_byte();
        mac[4] = rand_byte();
        mac[5] = rand_byte();

        Self {
            mac,
            features: super::feature::VIRTIO_F_VERSION_1,
            acked_features: 0,
        }
    }

    /// Create a new virtio-net device with a specific MAC address.
    pub fn with_mac(mac: [u8; 6]) -> Self {
        Self {
            mac,
            features: super::feature::VIRTIO_F_VERSION_1,
            acked_features: 0,
        }
    }

    /// Get the MAC address.
    pub fn mac(&self) -> &[u8; 6] {
        &self.mac
    }
}

impl Default for VirtioNet {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtioDevice for VirtioNet {
    fn device_type(&self) -> u32 {
        crate::device::device_type::NET
    }

    fn features(&self) -> u64 {
        self.features
    }

    fn ack_features(&mut self, features: u64) {
        self.acked_features = features & self.features;
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        // Config space contains MAC address at offset 0
        if offset < 6 && !data.is_empty() {
            let end = std::cmp::min(offset as usize + data.len(), 6);
            let len = end - offset as usize;
            data[..len].copy_from_slice(&self.mac[offset as usize..end]);
        }
    }

    fn write_config(&mut self, _offset: u64, _data: &[u8]) {
        // MAC address is read-only
    }

    fn activate(&mut self) -> Result<()> {
        // TODO: Set up virtqueues and start processing
        Ok(())
    }

    fn reset(&mut self) {
        self.acked_features = 0;
    }
}

/// Generate a pseudo-random byte.
fn rand_byte() -> u8 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    (nanos & 0xFF) as u8
}
