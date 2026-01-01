//! Virtio block device.
//!
//! TODO: Implement virtio-blk for guest disk access.

use crate::device::VirtioDevice;
use crate::error::Result;

use std::path::PathBuf;

/// Virtio block device.
pub struct VirtioBlk {
    /// Path to the disk image
    path: Option<PathBuf>,
    /// Disk size in bytes
    capacity: u64,
    /// Whether the disk is read-only
    readonly: bool,
    /// Device features
    features: u64,
    /// Acknowledged features
    acked_features: u64,
}

impl VirtioBlk {
    /// Create a new empty virtio-blk device.
    pub fn new() -> Self {
        Self {
            path: None,
            capacity: 0,
            readonly: false,
            features: super::feature::VIRTIO_F_VERSION_1,
            acked_features: 0,
        }
    }

    /// Create a virtio-blk device backed by a file.
    pub fn from_file(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let metadata = std::fs::metadata(&path)?;

        Ok(Self {
            capacity: metadata.len(),
            path: Some(path),
            readonly: false,
            features: super::feature::VIRTIO_F_VERSION_1,
            acked_features: 0,
        })
    }

    /// Set whether the device is read-only.
    pub fn set_readonly(&mut self, readonly: bool) {
        self.readonly = readonly;
    }

    /// Get the disk capacity in bytes.
    pub fn capacity(&self) -> u64 {
        self.capacity
    }
}

impl Default for VirtioBlk {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtioDevice for VirtioBlk {
    fn device_type(&self) -> u32 {
        crate::device::device_type::BLOCK
    }

    fn features(&self) -> u64 {
        self.features
    }

    fn ack_features(&mut self, features: u64) {
        self.acked_features = features & self.features;
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        // Config space layout (virtio spec 5.2.4):
        // offset 0: capacity (u64) - in 512-byte sectors
        // offset 8: size_max (u32)
        // offset 12: seg_max (u32)
        // ...

        let capacity_sectors = self.capacity / 512;

        if offset < 8 {
            let cap_bytes = capacity_sectors.to_le_bytes();
            let start = offset as usize;
            let end = std::cmp::min(start + data.len(), 8);
            let len = end - start;
            data[..len].copy_from_slice(&cap_bytes[start..end]);
        }
    }

    fn write_config(&mut self, _offset: u64, _data: &[u8]) {
        // Block device config is read-only
    }

    fn activate(&mut self) -> Result<()> {
        // TODO: Set up virtqueue and open backing file
        Ok(())
    }

    fn reset(&mut self) {
        self.acked_features = 0;
    }
}
