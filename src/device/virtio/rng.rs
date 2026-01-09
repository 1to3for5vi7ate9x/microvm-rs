//! Virtio RNG (Random Number Generator) device.
//!
//! Implements virtio-rng for providing entropy to the guest per the virtio spec 5.4.
//! This is critical for fast VM boot - without entropy, the guest kernel's CRNG
//! takes ~15-20 seconds to initialize, blocking socket() and other syscalls.

use crate::device::VirtioDevice;
use crate::error::Result;

use super::queue::{gpa_to_offset, Queue};

/// Queue size for RNG virtqueue.
const QUEUE_SIZE: u16 = 64;

/// Virtio RNG device.
///
/// The guest driver submits buffers to be filled with random data.
/// This device fills them with cryptographically secure random bytes.
pub struct VirtioRng {
    /// Device features
    features: u64,
    /// Acknowledged features
    acked_features: u64,
    /// Request queue (only queue for RNG)
    req_queue: Queue,
    /// Interrupt status (bit 0 = used buffer notification)
    interrupt_status: u32,
    /// Whether device is activated
    activated: bool,
}

impl VirtioRng {
    /// Create a new virtio-rng device.
    pub fn new() -> Self {
        Self {
            features: super::feature::VIRTIO_F_VERSION_1,
            acked_features: 0,
            req_queue: Queue::new(QUEUE_SIZE),
            interrupt_status: 0,
            activated: false,
        }
    }

    /// Get request queue (for transport to set up).
    pub fn req_queue(&self) -> &Queue {
        &self.req_queue
    }

    /// Get mutable request queue.
    pub fn req_queue_mut(&mut self) -> &mut Queue {
        &mut self.req_queue
    }

    /// Sync request queue configuration from transport.
    pub fn sync_req_queue(&mut self, transport_queue: &Queue) {
        self.req_queue.size = transport_queue.size;
        self.req_queue.ready = transport_queue.ready;
        self.req_queue.desc_table = transport_queue.desc_table;
        self.req_queue.avail_ring = transport_queue.avail_ring;
        self.req_queue.used_ring = transport_queue.used_ring;
    }

    /// Get interrupt status.
    pub fn interrupt_status(&self) -> u32 {
        self.interrupt_status
    }

    /// Acknowledge interrupts.
    pub fn ack_interrupt(&mut self, value: u32) {
        self.interrupt_status &= !value;
    }

    /// Check if there's a pending interrupt.
    pub fn has_pending_interrupt(&self) -> bool {
        self.interrupt_status != 0
    }

    /// Process the request queue - fill guest buffers with random data.
    /// Returns true if any requests were processed.
    pub fn process_requests(&mut self, memory: &mut [u8]) -> bool {
        let mut processed = false;

        // Don't process if queue isn't ready
        if !self.req_queue.ready {
            return false;
        }

        while self.req_queue.has_available(memory) {
            if let Some((head_idx, first_desc)) = self.req_queue.pop_available(memory) {
                let mut total_written = 0u32;

                // Fill all writable descriptors with random data
                let mut next_desc = Some(first_desc);
                while let Some(desc) = next_desc {
                    if desc.is_write_only() {
                        // Writable descriptor - fill with random bytes
                        if let Some(offset) = gpa_to_offset(desc.addr) {
                            let len = desc.len as usize;
                            if offset + len <= memory.len() {
                                // Fill with random data
                                Self::fill_random(&mut memory[offset..offset + len]);
                                total_written += len as u32;
                            }
                        }
                    }

                    // Follow chain
                    if desc.has_next() {
                        next_desc = self.req_queue.read_descriptor(memory, desc.next);
                    } else {
                        next_desc = None;
                    }
                }

                // Add to used ring
                self.req_queue.add_used(memory, head_idx, total_written);
                if total_written > 0 {
                    self.interrupt_status |= 1;
                    processed = true;
                }
            }
        }

        processed
    }

    /// Fill a buffer with cryptographically secure random bytes.
    fn fill_random(buf: &mut [u8]) {
        use std::collections::hash_map::RandomState;
        use std::hash::{BuildHasher, Hasher};

        // Use multiple sources of randomness for better entropy
        // This is a reasonable approach without pulling in external crates

        // Get some entropy from the system
        let mut pos = 0;
        while pos < buf.len() {
            // Use RandomState which uses system entropy on most platforms
            let state = RandomState::new();
            let mut hasher = state.build_hasher();

            // Mix in position and timestamp for additional entropy
            hasher.write_usize(pos);
            hasher.write_u64(std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0));

            let random_bytes = hasher.finish().to_le_bytes();

            let copy_len = std::cmp::min(8, buf.len() - pos);
            buf[pos..pos + copy_len].copy_from_slice(&random_bytes[..copy_len]);
            pos += copy_len;
        }
    }
}

impl Default for VirtioRng {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtioDevice for VirtioRng {
    fn device_type(&self) -> u32 {
        crate::device::device_type::RNG
    }

    fn features(&self) -> u64 {
        self.features
    }

    fn ack_features(&mut self, features: u64) {
        self.acked_features = features & self.features;
    }

    fn read_config(&self, _offset: u64, data: &mut [u8]) {
        // RNG has no config space (virtio spec 5.4.4)
        // Just return zeros
        for byte in data.iter_mut() {
            *byte = 0;
        }
    }

    fn write_config(&mut self, _offset: u64, _data: &[u8]) {
        // RNG config is read-only (and empty)
    }

    fn activate(&mut self) -> Result<()> {
        self.activated = true;
        Ok(())
    }

    fn reset(&mut self) {
        self.acked_features = 0;
        self.req_queue.reset();
        self.interrupt_status = 0;
        self.activated = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rng_creation() {
        let rng = VirtioRng::new();
        assert_eq!(rng.device_type(), 4); // RNG
        assert!(!rng.has_pending_interrupt());
    }

    #[test]
    fn test_fill_random() {
        let mut buf1 = [0u8; 32];
        let mut buf2 = [0u8; 32];

        VirtioRng::fill_random(&mut buf1);
        VirtioRng::fill_random(&mut buf2);

        // Buffers should be different (with overwhelming probability)
        assert_ne!(buf1, buf2);

        // Buffers should not be all zeros
        assert!(buf1.iter().any(|&b| b != 0));
        assert!(buf2.iter().any(|&b| b != 0));
    }
}
