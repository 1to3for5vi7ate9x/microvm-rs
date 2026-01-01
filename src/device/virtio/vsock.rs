//! Virtio vsock device.
//!
//! vsock provides a communication channel between the host and guest
//! without requiring network configuration. This is ideal for control
//! channels and is what Velocitty will use for VPN daemon communication.
//!
//! TODO: Implement virtio-vsock.

use crate::device::VirtioDevice;
use crate::error::Result;

/// Virtio vsock device.
pub struct VirtioVsock {
    /// Guest CID (Context ID)
    guest_cid: u64,
    /// Device features
    features: u64,
    /// Acknowledged features
    acked_features: u64,
}

impl VirtioVsock {
    /// Create a new virtio-vsock device with the specified guest CID.
    ///
    /// The CID must be >= 3 (0 is reserved, 1 is reserved for host, 2 is host).
    pub fn new(guest_cid: u64) -> Self {
        assert!(guest_cid >= 3, "Guest CID must be >= 3");

        Self {
            guest_cid,
            features: super::feature::VIRTIO_F_VERSION_1,
            acked_features: 0,
        }
    }

    /// Get the guest CID.
    pub fn guest_cid(&self) -> u64 {
        self.guest_cid
    }
}

impl VirtioDevice for VirtioVsock {
    fn device_type(&self) -> u32 {
        crate::device::device_type::VSOCK
    }

    fn features(&self) -> u64 {
        self.features
    }

    fn ack_features(&mut self, features: u64) {
        self.acked_features = features & self.features;
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        // Config space contains guest_cid as u64 at offset 0
        if offset < 8 {
            let cid_bytes = self.guest_cid.to_le_bytes();
            let start = offset as usize;
            let end = std::cmp::min(start + data.len(), 8);
            let len = end - start;
            data[..len].copy_from_slice(&cid_bytes[start..end]);
        }
    }

    fn write_config(&mut self, _offset: u64, _data: &[u8]) {
        // CID is read-only
    }

    fn activate(&mut self) -> Result<()> {
        // TODO: Set up virtqueues (rx, tx, event)
        Ok(())
    }

    fn reset(&mut self) {
        self.acked_features = 0;
    }
}
