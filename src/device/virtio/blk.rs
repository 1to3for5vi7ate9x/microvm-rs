//! Virtio block device.
//!
//! Implements virtio-blk for guest disk access per the virtio spec 5.2.

use crate::device::VirtioDevice;
use crate::error::Result;

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

use super::queue::Queue;

/// Virtio block device feature flags.
pub mod blk_features {
    /// Maximum size of any single segment is in size_max.
    pub const SIZE_MAX: u64 = 1 << 1;
    /// Maximum number of segments in a request is in seg_max.
    pub const SEG_MAX: u64 = 1 << 2;
    /// Disk-style geometry specified in geometry.
    pub const GEOMETRY: u64 = 1 << 4;
    /// Device is read-only.
    pub const RO: u64 = 1 << 5;
    /// Block size of disk is in blk_size.
    pub const BLK_SIZE: u64 = 1 << 6;
    /// Device supports flush command.
    pub const FLUSH: u64 = 1 << 9;
    /// Device exports information on optimal I/O alignment.
    pub const TOPOLOGY: u64 = 1 << 10;
    /// Device can toggle its cache between writeback and writethrough modes.
    pub const CONFIG_WCE: u64 = 1 << 11;
    /// Device supports multiqueue.
    pub const MQ: u64 = 1 << 12;
    /// Device can support discard command.
    pub const DISCARD: u64 = 1 << 13;
    /// Device can support write zeroes command.
    pub const WRITE_ZEROES: u64 = 1 << 14;
}

/// Block request types.
#[allow(dead_code)]
mod request_type {
    pub const IN: u32 = 0;      // Read
    pub const OUT: u32 = 1;     // Write
    pub const FLUSH: u32 = 4;   // Flush
    pub const GET_ID: u32 = 8;  // Get device ID
    pub const DISCARD: u32 = 11;
    pub const WRITE_ZEROES: u32 = 13;
}

/// Block request status.
mod request_status {
    pub const OK: u8 = 0;
    pub const IOERR: u8 = 1;
    pub const UNSUPP: u8 = 2;
}

/// Block request header (from guest).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct BlockRequestHeader {
    /// Request type (IN, OUT, FLUSH, etc.)
    request_type: u32,
    /// Reserved field.
    reserved: u32,
    /// Sector number for read/write.
    sector: u64,
}

const SECTOR_SIZE: u64 = 512;
const QUEUE_SIZE: u16 = 128;

/// Virtio block device.
pub struct VirtioBlk {
    /// Path to the disk image
    path: Option<PathBuf>,
    /// Backing file
    file: Option<File>,
    /// Disk size in bytes
    capacity: u64,
    /// Whether the disk is read-only
    readonly: bool,
    /// Device features
    features: u64,
    /// Acknowledged features
    acked_features: u64,
    /// Device status
    status: u8,
    /// Request queue
    queue: Queue,
    /// Interrupt status (bit 0 = used buffer notification)
    interrupt_status: u32,
    /// Configuration generation counter
    #[allow(dead_code)]
    config_generation: u32,
}

impl VirtioBlk {
    /// Create a new empty virtio-blk device.
    pub fn new() -> Self {
        Self {
            path: None,
            file: None,
            capacity: 0,
            readonly: false,
            features: super::feature::VIRTIO_F_VERSION_1 | blk_features::FLUSH,
            acked_features: 0,
            status: 0,
            queue: Queue::new(QUEUE_SIZE),
            interrupt_status: 0,
            config_generation: 0,
        }
    }

    /// Create a virtio-blk device backed by a file.
    pub fn from_file(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)?;

        let metadata = file.metadata()?;
        let capacity = metadata.len();

        Ok(Self {
            capacity,
            path: Some(path),
            file: Some(file),
            readonly: false,
            features: super::feature::VIRTIO_F_VERSION_1 | blk_features::FLUSH,
            acked_features: 0,
            status: 0,
            queue: Queue::new(QUEUE_SIZE),
            interrupt_status: 0,
            config_generation: 0,
        })
    }

    /// Create a read-only virtio-blk device backed by a file.
    pub fn from_file_readonly(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let file = OpenOptions::new()
            .read(true)
            .open(&path)?;

        let metadata = file.metadata()?;
        let capacity = metadata.len();

        Ok(Self {
            capacity,
            path: Some(path),
            file: Some(file),
            readonly: true,
            features: super::feature::VIRTIO_F_VERSION_1 | blk_features::FLUSH | blk_features::RO,
            acked_features: 0,
            status: 0,
            queue: Queue::new(QUEUE_SIZE),
            interrupt_status: 0,
            config_generation: 0,
        })
    }

    /// Set whether the device is read-only.
    pub fn set_readonly(&mut self, readonly: bool) {
        self.readonly = readonly;
        if readonly {
            self.features |= blk_features::RO;
        } else {
            self.features &= !blk_features::RO;
        }
    }

    /// Get the disk capacity in bytes.
    pub fn capacity(&self) -> u64 {
        self.capacity
    }

    /// Get the queue for this device.
    pub fn queue(&self) -> &Queue {
        &self.queue
    }

    /// Get a mutable reference to the queue.
    pub fn queue_mut(&mut self) -> &mut Queue {
        &mut self.queue
    }

    /// Get interrupt status.
    pub fn interrupt_status(&self) -> u32 {
        self.interrupt_status
    }

    /// Acknowledge interrupts.
    pub fn ack_interrupt(&mut self, value: u32) {
        self.interrupt_status &= !value;
    }

    /// Process a single block request.
    /// Returns the number of bytes written to the response (for used ring len field).
    pub fn process_request(&mut self, memory: &mut [u8]) -> Option<u32> {
        // Get the next available descriptor
        let (head_idx, first_desc) = self.queue.pop_available(memory)?;

        // First descriptor should be the request header (device-readable)
        if first_desc.is_write_only() || first_desc.len < 16 {
            // Invalid request - header must be readable and at least 16 bytes
            self.complete_request(memory, head_idx, request_status::IOERR);
            return Some(1);
        }

        // Read the request header
        let header = self.read_request_header(memory, first_desc.addr)?;

        // Collect all descriptors in the chain first to avoid borrow issues
        let mut descriptors = Vec::new();
        let mut next_idx = if first_desc.has_next() { Some(first_desc.next) } else { None };
        while let Some(idx) = next_idx {
            if let Some(desc) = self.queue.read_descriptor(memory, idx) {
                let has_next = desc.has_next();
                let next = desc.next;
                descriptors.push((desc.addr, desc.len, desc.is_write_only()));
                next_idx = if has_next { Some(next) } else { None };
            } else {
                break;
            }
        }

        // Process based on request type
        let status = match header.request_type {
            request_type::IN => self.process_read_descs(memory, &descriptors, header.sector),
            request_type::OUT => self.process_write_descs(memory, &descriptors, header.sector),
            request_type::FLUSH => self.process_flush(),
            request_type::GET_ID => self.process_get_id_descs(memory, &descriptors),
            _ => request_status::UNSUPP,
        };

        // Find the status descriptor and write the status
        // The last descriptor in the chain should be the status byte
        let total_len = self.complete_request(memory, head_idx, status);

        Some(total_len)
    }

    /// Read request header from guest memory.
    fn read_request_header(&self, memory: &[u8], addr: u64) -> Option<BlockRequestHeader> {
        let offset = addr as usize;
        if offset + 16 > memory.len() {
            return None;
        }

        Some(BlockRequestHeader {
            request_type: u32::from_le_bytes(memory[offset..offset + 4].try_into().ok()?),
            reserved: u32::from_le_bytes(memory[offset + 4..offset + 8].try_into().ok()?),
            sector: u64::from_le_bytes(memory[offset + 8..offset + 16].try_into().ok()?),
        })
    }

    /// Process a read request using pre-collected descriptors.
    fn process_read_descs(
        &mut self,
        memory: &mut [u8],
        descriptors: &[(u64, u32, bool)], // (addr, len, is_write_only)
        sector: u64,
    ) -> u8 {
        let file = match &mut self.file {
            Some(f) => f,
            None => return request_status::IOERR,
        };

        let byte_offset = sector * SECTOR_SIZE;
        if file.seek(SeekFrom::Start(byte_offset)).is_err() {
            return request_status::IOERR;
        }

        // Process data descriptors (device-writable)
        for &(addr, len, is_write) in descriptors {
            if !is_write {
                // Skip non-writable descriptors
                continue;
            }

            let offset = addr as usize;
            let len = len as usize;

            // Skip if this is just 1 byte (likely the status descriptor)
            if len == 1 {
                continue;
            }

            if offset + len > memory.len() {
                return request_status::IOERR;
            }

            // Read from file into guest memory
            if file.read_exact(&mut memory[offset..offset + len]).is_err() {
                return request_status::IOERR;
            }
        }

        request_status::OK
    }

    /// Process a write request using pre-collected descriptors.
    fn process_write_descs(
        &mut self,
        memory: &[u8],
        descriptors: &[(u64, u32, bool)], // (addr, len, is_write_only)
        sector: u64,
    ) -> u8 {
        if self.readonly {
            return request_status::IOERR;
        }

        let file = match &mut self.file {
            Some(f) => f,
            None => return request_status::IOERR,
        };

        let byte_offset = sector * SECTOR_SIZE;
        if file.seek(SeekFrom::Start(byte_offset)).is_err() {
            return request_status::IOERR;
        }

        // Process data descriptors (device-readable for writes)
        for &(addr, len, is_write) in descriptors {
            if is_write {
                // Skip writable descriptors (status)
                continue;
            }

            let offset = addr as usize;
            let len = len as usize;

            if offset + len > memory.len() {
                return request_status::IOERR;
            }

            // Write from guest memory to file
            if file.write_all(&memory[offset..offset + len]).is_err() {
                return request_status::IOERR;
            }
        }

        request_status::OK
    }

    /// Process a flush request.
    fn process_flush(&mut self) -> u8 {
        let file = match &mut self.file {
            Some(f) => f,
            None => return request_status::IOERR,
        };

        if file.sync_all().is_err() {
            return request_status::IOERR;
        }

        request_status::OK
    }

    /// Process a get ID request using pre-collected descriptors.
    fn process_get_id_descs(
        &self,
        memory: &mut [u8],
        descriptors: &[(u64, u32, bool)],
    ) -> u8 {
        // Get the device ID (up to 20 bytes)
        let id = match &self.path {
            Some(p) => p.to_string_lossy().into_owned(),
            None => "microvm-blk".to_string(),
        };
        let id_bytes = id.as_bytes();

        // Find the data descriptor
        for &(addr, len, is_write) in descriptors {
            if !is_write || len == 1 {
                continue;
            }

            let offset = addr as usize;
            let len = std::cmp::min(len as usize, 20);

            if offset + len > memory.len() {
                return request_status::IOERR;
            }

            let copy_len = std::cmp::min(len, id_bytes.len());
            memory[offset..offset + copy_len].copy_from_slice(&id_bytes[..copy_len]);

            // Pad with zeros
            for byte in &mut memory[offset + copy_len..offset + len] {
                *byte = 0;
            }

            return request_status::OK;
        }

        request_status::IOERR
    }

    /// Complete a request by writing status and adding to used ring.
    fn complete_request(&mut self, memory: &mut [u8], head_idx: u16, status: u8) -> u32 {
        // Find the status descriptor (last one, writable, 1 byte)
        // We need to traverse the chain to find it
        let mut total_len = 0u32;
        let mut status_addr = None;

        let mut next_idx = Some(head_idx);
        while let Some(idx) = next_idx {
            if let Some(desc) = self.queue.read_descriptor(memory, idx) {
                if desc.is_write_only() {
                    total_len += desc.len;
                    if desc.len == 1 {
                        status_addr = Some(desc.addr);
                    }
                }
                next_idx = if desc.has_next() { Some(desc.next) } else { None };
            } else {
                break;
            }
        }

        // Write status
        if let Some(addr) = status_addr {
            let offset = addr as usize;
            if offset < memory.len() {
                memory[offset] = status;
            }
        }

        // Add to used ring
        self.queue.add_used(memory, head_idx, total_len);

        // Set interrupt
        self.interrupt_status |= 1;

        total_len
    }

    /// Process all pending requests.
    pub fn process_queue(&mut self, memory: &mut [u8]) -> bool {
        let mut processed = false;
        while self.queue.has_available(memory) {
            if self.process_request(memory).is_some() {
                processed = true;
            } else {
                break;
            }
        }
        processed
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
        // offset 16: geometry (cylinders u16, heads u8, sectors u8)
        // offset 20: blk_size (u32)
        // ...

        let capacity_sectors = self.capacity / SECTOR_SIZE;
        let config = [
            // capacity (8 bytes)
            capacity_sectors.to_le_bytes(),
            // size_max (4 bytes) - padded to 8
            [0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0x00], // 1MB size_max, 128 seg_max
        ];

        let config_bytes: Vec<u8> = config.iter().flat_map(|b| b.iter().copied()).collect();

        let start = offset as usize;
        let end = std::cmp::min(start + data.len(), config_bytes.len());
        if start < config_bytes.len() {
            let len = end - start;
            data[..len].copy_from_slice(&config_bytes[start..end]);
        }
    }

    fn write_config(&mut self, _offset: u64, _data: &[u8]) {
        // Block device config is read-only
    }

    fn activate(&mut self) -> Result<()> {
        // Device is already set up, nothing more to do
        Ok(())
    }

    fn reset(&mut self) {
        self.acked_features = 0;
        self.status = 0;
        self.queue.reset();
        self.interrupt_status = 0;
    }
}
