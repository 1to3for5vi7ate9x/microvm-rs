//! Virtio queue (virtqueue) implementation.
//!
//! This implements the split virtqueue layout as described in the virtio spec.

use std::sync::atomic::{fence, Ordering};

/// Maximum queue size.
pub const MAX_QUEUE_SIZE: u16 = 256;

/// RAM base address - guest physical addresses start here.
/// The memory slice passed to queue operations represents RAM starting at this address.
pub const RAM_BASE: u64 = 0x4000_0000;

/// Convert a guest physical address to a memory slice offset.
/// Returns None if the address is below RAM_BASE.
#[inline]
pub fn gpa_to_offset(gpa: u64) -> Option<usize> {
    if gpa >= RAM_BASE {
        Some((gpa - RAM_BASE) as usize)
    } else {
        None
    }
}

/// Virtqueue descriptor flags.
pub mod desc_flags {
    /// This marks a buffer as continuing via the next field.
    pub const NEXT: u16 = 1;
    /// This marks a buffer as device write-only (vs read-only).
    pub const WRITE: u16 = 2;
    /// This means the buffer contains a list of buffer descriptors.
    pub const INDIRECT: u16 = 4;
}

/// A single virtqueue descriptor.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Descriptor {
    /// Guest physical address of the buffer.
    pub addr: u64,
    /// Length of the buffer.
    pub len: u32,
    /// Descriptor flags.
    pub flags: u16,
    /// Next descriptor index if NEXT flag is set.
    pub next: u16,
}

impl Descriptor {
    /// Check if this descriptor has the NEXT flag set.
    pub fn has_next(&self) -> bool {
        self.flags & desc_flags::NEXT != 0
    }

    /// Check if this descriptor is device write-only.
    pub fn is_write_only(&self) -> bool {
        self.flags & desc_flags::WRITE != 0
    }
}

/// Available ring entry.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct AvailRingEntry {
    pub id: u16,
}

/// Used ring entry.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct UsedRingEntry {
    /// Index of the descriptor chain.
    pub id: u32,
    /// Total length written to the descriptor chain.
    pub len: u32,
}

/// Virtqueue configuration and state.
#[derive(Clone)]
pub struct Queue {
    /// Queue size (number of descriptors).
    pub size: u16,
    /// Whether the queue is ready.
    pub ready: bool,
    /// Descriptor table guest physical address.
    pub desc_table: u64,
    /// Available ring guest physical address.
    pub avail_ring: u64,
    /// Used ring guest physical address.
    pub used_ring: u64,
    /// Last seen available index.
    pub last_avail_idx: u16,
    /// Next used index to write.
    pub next_used_idx: u16,
}

impl Queue {
    /// Create a new queue.
    pub fn new(max_size: u16) -> Self {
        Self {
            size: max_size,
            ready: false,
            desc_table: 0,
            avail_ring: 0,
            used_ring: 0,
            last_avail_idx: 0,
            next_used_idx: 0,
        }
    }

    /// Reset the queue.
    pub fn reset(&mut self) {
        self.ready = false;
        self.desc_table = 0;
        self.avail_ring = 0;
        self.used_ring = 0;
        self.last_avail_idx = 0;
        self.next_used_idx = 0;
    }

    /// Check if there are available descriptors to process.
    pub fn has_available(&self, memory: &[u8]) -> bool {
        if !self.ready {
            return false;
        }

        let avail_idx = self.read_avail_idx(memory);
        avail_idx != self.last_avail_idx
    }

    /// Get the next available descriptor chain head.
    /// Returns (descriptor_index, descriptor) if available.
    pub fn pop_available(&mut self, memory: &[u8]) -> Option<(u16, Descriptor)> {
        if !self.ready {
            return None;
        }

        let avail_idx = self.read_avail_idx(memory);
        if avail_idx == self.last_avail_idx {
            return None;
        }

        // Memory barrier to ensure we see the descriptor after the index
        fence(Ordering::Acquire);

        // Calculate the ring index
        let ring_idx = (self.last_avail_idx % self.size) as usize;

        // Read the descriptor index from the available ring
        // Available ring layout: flags (u16), idx (u16), ring[size] (u16 each)
        let avail_ring_base = gpa_to_offset(self.avail_ring)?;
        let avail_ring_offset = avail_ring_base + 4 + ring_idx * 2;
        if avail_ring_offset + 2 > memory.len() {
            return None;
        }
        let desc_idx = u16::from_le_bytes([
            memory[avail_ring_offset],
            memory[avail_ring_offset + 1],
        ]);

        // Read the descriptor
        let desc = self.read_descriptor(memory, desc_idx)?;

        self.last_avail_idx = self.last_avail_idx.wrapping_add(1);
        Some((desc_idx, desc))
    }

    /// Read a descriptor from the descriptor table.
    pub fn read_descriptor(&self, memory: &[u8], index: u16) -> Option<Descriptor> {
        let desc_base = gpa_to_offset(self.desc_table)?;
        let offset = desc_base + (index as usize) * 16;
        if offset + 16 > memory.len() {
            return None;
        }

        Some(Descriptor {
            addr: u64::from_le_bytes(memory[offset..offset + 8].try_into().ok()?),
            len: u32::from_le_bytes(memory[offset + 8..offset + 12].try_into().ok()?),
            flags: u16::from_le_bytes(memory[offset + 12..offset + 14].try_into().ok()?),
            next: u16::from_le_bytes(memory[offset + 14..offset + 16].try_into().ok()?),
        })
    }

    /// Add an entry to the used ring.
    pub fn add_used(&mut self, memory: &mut [u8], desc_idx: u16, len: u32) {
        if !self.ready {
            return;
        }

        // Calculate the ring index
        let ring_idx = (self.next_used_idx % self.size) as usize;

        // Used ring layout: flags (u16), idx (u16), ring[size] (id u32, len u32 each)
        let used_ring_base = match gpa_to_offset(self.used_ring) {
            Some(base) => base,
            None => return,
        };
        let used_ring_offset = used_ring_base + 4 + ring_idx * 8;
        if used_ring_offset + 8 > memory.len() {
            return;
        }

        // Write the used entry
        let entry_bytes = [
            (desc_idx as u32).to_le_bytes(),
            len.to_le_bytes(),
        ];
        memory[used_ring_offset..used_ring_offset + 4].copy_from_slice(&entry_bytes[0]);
        memory[used_ring_offset + 4..used_ring_offset + 8].copy_from_slice(&entry_bytes[1]);

        // Memory barrier before updating the index
        fence(Ordering::Release);

        // Update the used index
        self.next_used_idx = self.next_used_idx.wrapping_add(1);
        let idx_offset = used_ring_base + 2;
        if idx_offset + 2 <= memory.len() {
            memory[idx_offset..idx_offset + 2].copy_from_slice(&self.next_used_idx.to_le_bytes());
        }
    }

    /// Read the available ring index from memory.
    fn read_avail_idx(&self, memory: &[u8]) -> u16 {
        let offset = match gpa_to_offset(self.avail_ring) {
            Some(base) => base + 2,
            None => return self.last_avail_idx,
        };
        if offset + 2 > memory.len() {
            return self.last_avail_idx;
        }
        u16::from_le_bytes([memory[offset], memory[offset + 1]])
    }
}

impl Default for Queue {
    fn default() -> Self {
        Self::new(MAX_QUEUE_SIZE)
    }
}

/// Iterator over a descriptor chain.
pub struct DescriptorChain<'a> {
    memory: &'a [u8],
    queue: &'a Queue,
    next_index: Option<u16>,
}

impl<'a> DescriptorChain<'a> {
    /// Create a new descriptor chain iterator.
    pub fn new(memory: &'a [u8], queue: &'a Queue, head: u16) -> Self {
        Self {
            memory,
            queue,
            next_index: Some(head),
        }
    }
}

impl<'a> Iterator for DescriptorChain<'a> {
    type Item = (u16, Descriptor);

    fn next(&mut self) -> Option<Self::Item> {
        let index = self.next_index?;
        let desc = self.queue.read_descriptor(self.memory, index)?;

        self.next_index = if desc.has_next() {
            Some(desc.next)
        } else {
            None
        };

        Some((index, desc))
    }
}
