//! Virtio console device.
//!
//! Implements virtio-console for guest console I/O per the virtio spec 5.3.

use crate::device::VirtioDevice;
use crate::error::Result;
use std::collections::VecDeque;
use std::io::{Read, Write};

use super::queue::{gpa_to_offset, Queue};

/// Queue size for console virtqueues.
const QUEUE_SIZE: u16 = 64;

/// Console feature flags.
pub mod console_features {
    /// Multiple ports supported (we don't use this for simplicity).
    pub const MULTIPORT: u64 = 1 << 0;
    /// Emergency write supported.
    pub const EMERG_WRITE: u64 = 1 << 1;
}

/// Virtio console device.
pub struct VirtioConsole {
    /// Device features
    features: u64,
    /// Acknowledged features
    acked_features: u64,
    /// RX queue (receiveq - guest receives data)
    rx_queue: Queue,
    /// TX queue (transmitq - guest sends data)
    tx_queue: Queue,
    /// Input buffer (data waiting to be read by guest)
    input_buffer: VecDeque<u8>,
    /// Interrupt status (bit 0 = used buffer notification)
    interrupt_status: u32,
    /// Whether device is activated
    activated: bool,
}

impl VirtioConsole {
    /// Create a new virtio-console device.
    pub fn new() -> Self {
        Self {
            features: super::feature::VIRTIO_F_VERSION_1,
            acked_features: 0,
            rx_queue: Queue::new(QUEUE_SIZE),
            tx_queue: Queue::new(QUEUE_SIZE),
            input_buffer: VecDeque::new(),
            interrupt_status: 0,
            activated: false,
        }
    }

    /// Get RX queue (for transport to set up).
    pub fn rx_queue(&self) -> &Queue {
        &self.rx_queue
    }

    /// Get TX queue (for transport to set up).
    pub fn tx_queue(&self) -> &Queue {
        &self.tx_queue
    }

    /// Get mutable RX queue.
    pub fn rx_queue_mut(&mut self) -> &mut Queue {
        &mut self.rx_queue
    }

    /// Get mutable TX queue.
    pub fn tx_queue_mut(&mut self) -> &mut Queue {
        &mut self.tx_queue
    }

    /// Sync RX queue configuration from transport.
    /// Only syncs configuration (addresses, size, ready), not runtime state (indices).
    pub fn sync_rx_queue(&mut self, transport_queue: &Queue) {
        self.rx_queue.size = transport_queue.size;
        self.rx_queue.ready = transport_queue.ready;
        self.rx_queue.desc_table = transport_queue.desc_table;
        self.rx_queue.avail_ring = transport_queue.avail_ring;
        self.rx_queue.used_ring = transport_queue.used_ring;
        // Note: Don't sync last_avail_idx and next_used_idx - these are device runtime state
    }

    /// Sync TX queue configuration from transport.
    /// Only syncs configuration (addresses, size, ready), not runtime state (indices).
    pub fn sync_tx_queue(&mut self, transport_queue: &Queue) {
        self.tx_queue.size = transport_queue.size;
        self.tx_queue.ready = transport_queue.ready;
        self.tx_queue.desc_table = transport_queue.desc_table;
        self.tx_queue.avail_ring = transport_queue.avail_ring;
        self.tx_queue.used_ring = transport_queue.used_ring;
        // Note: Don't sync last_avail_idx and next_used_idx - these are device runtime state
    }

    /// Get interrupt status.
    pub fn interrupt_status(&self) -> u32 {
        self.interrupt_status
    }

    /// Acknowledge interrupts.
    pub fn ack_interrupt(&mut self, value: u32) {
        self.interrupt_status &= !value;
    }

    /// Queue input data to be sent to guest.
    pub fn queue_input(&mut self, data: &[u8]) {
        self.input_buffer.extend(data);
    }

    /// Process the TX queue (guest -> host output).
    /// Returns the data written by the guest.
    pub fn process_tx(&mut self, memory: &mut [u8]) -> Vec<u8> {
        let mut output = Vec::new();

        while self.tx_queue.has_available(memory) {
            if let Some((head_idx, first_desc)) = self.tx_queue.pop_available(memory) {
                // Read data from descriptor chain
                let mut next_desc = Some(first_desc);
                while let Some(desc) = next_desc {
                    if !desc.is_write_only() {
                        // Readable descriptor contains data from guest
                        // Convert guest physical address to memory offset
                        if let Some(offset) = gpa_to_offset(desc.addr) {
                            let len = desc.len as usize;
                            if offset + len <= memory.len() {
                                output.extend_from_slice(&memory[offset..offset + len]);
                            }
                        }
                    }

                    // Follow chain
                    if desc.has_next() {
                        next_desc = self.tx_queue.read_descriptor(memory, desc.next);
                    } else {
                        next_desc = None;
                    }
                }

                // Add to used ring (we consumed all data)
                self.tx_queue.add_used(memory, head_idx, 0);
                self.interrupt_status |= 1;
            }
        }

        output
    }

    /// Process the RX queue (host -> guest input).
    /// Delivers queued input data to the guest.
    /// Returns true if any data was delivered.
    pub fn process_rx(&mut self, memory: &mut [u8]) -> bool {
        let mut delivered = false;

        while !self.input_buffer.is_empty() && self.rx_queue.has_available(memory) {
            if let Some((head_idx, first_desc)) = self.rx_queue.pop_available(memory) {
                let mut total_written = 0u32;

                // Write data to descriptor chain
                let mut next_desc = Some(first_desc);
                while let Some(desc) = next_desc {
                    if desc.is_write_only() && !self.input_buffer.is_empty() {
                        // Writable descriptor - we can write input data here
                        // Convert guest physical address to memory offset
                        if let Some(offset) = gpa_to_offset(desc.addr) {
                            let len = desc.len as usize;
                            if offset + len <= memory.len() {
                                let to_write = std::cmp::min(len, self.input_buffer.len());
                                for i in 0..to_write {
                                    if let Some(byte) = self.input_buffer.pop_front() {
                                        memory[offset + i] = byte;
                                        total_written += 1;
                                    }
                                }
                            }
                        }
                    }

                    // Follow chain
                    if desc.has_next() {
                        next_desc = self.rx_queue.read_descriptor(memory, desc.next);
                    } else {
                        next_desc = None;
                    }
                }

                if total_written > 0 {
                    // Add to used ring
                    self.rx_queue.add_used(memory, head_idx, total_written);
                    self.interrupt_status |= 1;
                    delivered = true;
                }
            }
        }

        delivered
    }

    /// Check if there's pending input to deliver.
    pub fn has_pending_input(&self) -> bool {
        !self.input_buffer.is_empty()
    }

    /// Check if there's a pending interrupt.
    pub fn has_pending_interrupt(&self) -> bool {
        self.interrupt_status != 0
    }

    /// Process both TX and RX queues.
    /// Writes TX output to the provided writer and reads RX input from reader.
    pub fn process<W: Write, R: Read>(
        &mut self,
        memory: &mut [u8],
        writer: &mut W,
        reader: Option<&mut R>,
    ) -> Result<()> {
        // Process TX (guest output)
        let output = self.process_tx(memory);
        if !output.is_empty() {
            let _ = writer.write_all(&output);
            let _ = writer.flush();
        }

        // Read input if available
        if let Some(reader) = reader {
            let mut buf = [0u8; 256];
            if let Ok(n) = reader.read(&mut buf) {
                if n > 0 {
                    self.queue_input(&buf[..n]);
                }
            }
        }

        // Process RX (deliver input to guest)
        self.process_rx(memory);

        Ok(())
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

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        // Console config space (virtio spec 5.3.4):
        // offset 0: cols (u16) - optional, 0 = unknown
        // offset 2: rows (u16) - optional, 0 = unknown
        // offset 4: max_nr_ports (u32) - only if MULTIPORT
        // offset 8: emerg_wr (u32) - only if EMERG_WRITE
        //
        // For a simple console, we return zeros (unknown size, no ports)
        let config = [0u8; 16];
        let start = offset as usize;
        let end = std::cmp::min(start + data.len(), config.len());
        if start < config.len() {
            data[..end - start].copy_from_slice(&config[start..end]);
        }
    }

    fn write_config(&mut self, _offset: u64, _data: &[u8]) {
        // Console config is read-only
    }

    fn activate(&mut self) -> Result<()> {
        self.activated = true;
        Ok(())
    }

    fn reset(&mut self) {
        self.acked_features = 0;
        self.rx_queue.reset();
        self.tx_queue.reset();
        self.input_buffer.clear();
        self.interrupt_status = 0;
        self.activated = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_console_creation() {
        let console = VirtioConsole::new();
        assert_eq!(console.device_type(), 3); // CONSOLE
        assert!(!console.has_pending_input());
    }

    #[test]
    fn test_input_buffer() {
        let mut console = VirtioConsole::new();
        console.queue_input(b"hello");
        assert!(console.has_pending_input());
        assert_eq!(console.input_buffer.len(), 5);
    }
}
