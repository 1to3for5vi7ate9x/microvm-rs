//! Virtio network device.
//!
//! Implements virtio-net for guest networking. Supports both TAP backend
//! (for bridged networking) and user-mode networking (NAT/SOCKS).
//!
//! ## Virtqueues
//!
//! | Queue | Direction | Purpose |
//! |-------|-----------|---------|
//! | 0     | RX        | Receive packets from host to guest |
//! | 1     | TX        | Transmit packets from guest to host |

use crate::device::VirtioDevice;
use crate::error::Result;
use std::collections::VecDeque;

use super::queue::Queue;

const RX_QUEUE: usize = 0;
const TX_QUEUE: usize = 1;
const QUEUE_SIZE: u16 = 256;

/// Virtio-net feature bits.
#[allow(dead_code)]
pub mod feature {
    pub const VIRTIO_NET_F_CSUM: u64 = 1 << 0;
    pub const VIRTIO_NET_F_GUEST_CSUM: u64 = 1 << 1;
    pub const VIRTIO_NET_F_MAC: u64 = 1 << 5;
    pub const VIRTIO_NET_F_GSO: u64 = 1 << 6;
    pub const VIRTIO_NET_F_GUEST_TSO4: u64 = 1 << 7;
    pub const VIRTIO_NET_F_GUEST_TSO6: u64 = 1 << 8;
    pub const VIRTIO_NET_F_GUEST_ECN: u64 = 1 << 9;
    pub const VIRTIO_NET_F_GUEST_UFO: u64 = 1 << 10;
    pub const VIRTIO_NET_F_HOST_TSO4: u64 = 1 << 11;
    pub const VIRTIO_NET_F_HOST_TSO6: u64 = 1 << 12;
    pub const VIRTIO_NET_F_HOST_ECN: u64 = 1 << 13;
    pub const VIRTIO_NET_F_HOST_UFO: u64 = 1 << 14;
    pub const VIRTIO_NET_F_MRG_RXBUF: u64 = 1 << 15;
    pub const VIRTIO_NET_F_STATUS: u64 = 1 << 16;
    pub const VIRTIO_NET_F_CTRL_VQ: u64 = 1 << 17;
    pub const VIRTIO_NET_F_CTRL_RX: u64 = 1 << 18;
    pub const VIRTIO_NET_F_CTRL_VLAN: u64 = 1 << 19;
    pub const VIRTIO_NET_F_GUEST_ANNOUNCE: u64 = 1 << 21;
    pub const VIRTIO_NET_F_MQ: u64 = 1 << 22;
    pub const VIRTIO_NET_F_CTRL_MAC_ADDR: u64 = 1 << 23;
}

/// Virtio-net header (prepended to each packet).
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct VirtioNetHeader {
    pub flags: u8,
    pub gso_type: u8,
    pub hdr_len: u16,
    pub gso_size: u16,
    pub csum_start: u16,
    pub csum_offset: u16,
    pub num_buffers: u16,
}

impl VirtioNetHeader {
    pub const SIZE: usize = 12; // Size with num_buffers (mergeable rx buffers)
    pub const SIZE_LEGACY: usize = 10; // Size without num_buffers
}

/// Network backend trait for different networking modes.
pub trait NetBackend: Send {
    /// Receive a packet (returns None if no packet available).
    fn recv(&mut self) -> Option<Vec<u8>>;

    /// Send a packet.
    fn send(&mut self, data: &[u8]) -> Result<()>;

    /// Check if there's data available to read.
    fn has_data(&self) -> bool;
}

/// Null network backend (drops all packets).
pub struct NullBackend;

impl NetBackend for NullBackend {
    fn recv(&mut self) -> Option<Vec<u8>> {
        None
    }

    fn send(&mut self, _data: &[u8]) -> Result<()> {
        Ok(())
    }

    fn has_data(&self) -> bool {
        false
    }
}

/// Loopback network backend (echoes packets back).
pub struct LoopbackBackend {
    queue: VecDeque<Vec<u8>>,
}

impl LoopbackBackend {
    pub fn new() -> Self {
        Self {
            queue: VecDeque::new(),
        }
    }
}

impl Default for LoopbackBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl NetBackend for LoopbackBackend {
    fn recv(&mut self) -> Option<Vec<u8>> {
        self.queue.pop_front()
    }

    fn send(&mut self, data: &[u8]) -> Result<()> {
        self.queue.push_back(data.to_vec());
        Ok(())
    }

    fn has_data(&self) -> bool {
        !self.queue.is_empty()
    }
}

/// Virtio network device.
pub struct VirtioNet {
    /// MAC address
    mac: [u8; 6],
    /// Device features
    features: u64,
    /// Acknowledged features
    acked_features: u64,
    /// Link status (1 = up, 0 = down)
    link_status: u16,
    /// Network backend
    backend: Box<dyn NetBackend>,
    /// RX queue pending packets
    rx_pending: VecDeque<Vec<u8>>,
    /// Is the device activated?
    activated: bool,
    /// RX virtqueue
    rx_queue: Queue,
    /// TX virtqueue
    tx_queue: Queue,
    /// Interrupt status
    interrupt_status: u32,
}

impl VirtioNet {
    /// Default features we support.
    const DEFAULT_FEATURES: u64 = feature::VIRTIO_NET_F_MAC
        | feature::VIRTIO_NET_F_STATUS
        | super::feature::VIRTIO_F_VERSION_1;

    /// Create a new virtio-net device with a random MAC address.
    pub fn new() -> Self {
        Self::with_backend(Box::new(NullBackend))
    }

    /// Create a new virtio-net device with a specific MAC address.
    pub fn with_mac(mac: [u8; 6]) -> Self {
        let mut net = Self::new();
        net.mac = mac;
        net
    }

    /// Create a new virtio-net device with a custom backend.
    pub fn with_backend(backend: Box<dyn NetBackend>) -> Self {
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
            features: Self::DEFAULT_FEATURES,
            acked_features: 0,
            link_status: 1, // Link up
            backend,
            rx_pending: VecDeque::new(),
            activated: false,
            rx_queue: Queue::new(QUEUE_SIZE),
            tx_queue: Queue::new(QUEUE_SIZE),
            interrupt_status: 0,
        }
    }

    /// Get the MAC address.
    pub fn mac(&self) -> &[u8; 6] {
        &self.mac
    }

    /// Set the MAC address.
    pub fn set_mac(&mut self, mac: [u8; 6]) {
        self.mac = mac;
    }

    /// Set link status.
    pub fn set_link_up(&mut self, up: bool) {
        self.link_status = if up { 1 } else { 0 };
    }

    /// Check if device is activated.
    pub fn is_activated(&self) -> bool {
        self.activated
    }

    /// Queue a packet for the guest to receive.
    pub fn queue_rx(&mut self, data: Vec<u8>) {
        self.rx_pending.push_back(data);
    }

    /// Get next pending RX packet.
    pub fn pop_rx(&mut self) -> Option<Vec<u8>> {
        // First check pending queue
        if let Some(pkt) = self.rx_pending.pop_front() {
            return Some(pkt);
        }
        // Then check backend
        self.backend.recv()
    }

    /// Send a packet to the network.
    pub fn send_packet(&mut self, data: &[u8]) -> Result<()> {
        self.backend.send(data)
    }

    /// Check if there are packets available for RX.
    pub fn has_rx_data(&self) -> bool {
        !self.rx_pending.is_empty() || self.backend.has_data()
    }

    /// Get the RX queue.
    pub fn rx_queue(&self) -> &Queue {
        &self.rx_queue
    }

    /// Get the RX queue mutably.
    pub fn rx_queue_mut(&mut self) -> &mut Queue {
        &mut self.rx_queue
    }

    /// Get the TX queue.
    pub fn tx_queue(&self) -> &Queue {
        &self.tx_queue
    }

    /// Get the TX queue mutably.
    pub fn tx_queue_mut(&mut self) -> &mut Queue {
        &mut self.tx_queue
    }

    /// Get queue by index.
    pub fn queue(&self, idx: usize) -> Option<&Queue> {
        match idx {
            RX_QUEUE => Some(&self.rx_queue),
            TX_QUEUE => Some(&self.tx_queue),
            _ => None,
        }
    }

    /// Get queue by index mutably.
    pub fn queue_mut(&mut self, idx: usize) -> Option<&mut Queue> {
        match idx {
            RX_QUEUE => Some(&mut self.rx_queue),
            TX_QUEUE => Some(&mut self.tx_queue),
            _ => None,
        }
    }

    /// Get interrupt status.
    pub fn interrupt_status(&self) -> u32 {
        self.interrupt_status
    }

    /// Acknowledge interrupts.
    pub fn ack_interrupt(&mut self, value: u32) {
        self.interrupt_status &= !value;
    }

    /// Process TX queue - send packets from guest to backend.
    pub fn process_tx(&mut self, memory: &[u8]) -> bool {
        let mut processed = false;

        // Don't process if queue isn't ready
        if !self.tx_queue.ready {
            return false;
        }

        while let Some((head_idx, first_desc)) = self.tx_queue.pop_available(memory) {
            // Collect the packet data from the descriptor chain
            let mut packet_data = Vec::new();
            let mut skip_header = true;

            // First descriptor
            if !first_desc.is_write_only() {
                let offset = first_desc.addr as usize;
                let len = first_desc.len as usize;
                if offset + len <= memory.len() {
                    if skip_header && len >= VirtioNetHeader::SIZE {
                        // Skip the virtio-net header
                        packet_data.extend_from_slice(&memory[offset + VirtioNetHeader::SIZE..offset + len]);
                        skip_header = false;
                    } else if !skip_header {
                        packet_data.extend_from_slice(&memory[offset..offset + len]);
                    }
                }
            }

            // Follow the chain
            let mut next_idx = if first_desc.has_next() { Some(first_desc.next) } else { None };
            while let Some(idx) = next_idx {
                if let Some(desc) = self.tx_queue.read_descriptor(memory, idx) {
                    if !desc.is_write_only() {
                        let offset = desc.addr as usize;
                        let len = desc.len as usize;
                        if offset + len <= memory.len() {
                            packet_data.extend_from_slice(&memory[offset..offset + len]);
                        }
                    }
                    next_idx = if desc.has_next() { Some(desc.next) } else { None };
                } else {
                    break;
                }
            }

            // Send the packet
            if !packet_data.is_empty() {
                let _ = self.backend.send(&packet_data);
            }

            // Add to used ring (no data written for TX)
            // Note: We need mutable access to memory for add_used, but we only have &[u8]
            // This is a design limitation - in practice, this needs to be called with &mut memory
            processed = true;

            // Mark as used (we'll handle this externally since we can't modify memory here)
        }

        if processed {
            self.interrupt_status |= 1;
        }

        processed
    }

    /// Process TX queue with mutable memory access.
    pub fn process_tx_mut(&mut self, memory: &mut [u8]) -> bool {
        let mut processed = false;

        // Don't process if queue isn't ready
        if !self.tx_queue.ready {
            return false;
        }

        while let Some((head_idx, first_desc)) = self.tx_queue.pop_available(memory) {
            // Collect the packet data from the descriptor chain
            let mut packet_data = Vec::new();
            let mut skip_header = true;

            // First descriptor
            if !first_desc.is_write_only() {
                let offset = first_desc.addr as usize;
                let len = first_desc.len as usize;
                if offset + len <= memory.len() {
                    if skip_header && len >= VirtioNetHeader::SIZE {
                        // Skip the virtio-net header
                        packet_data.extend_from_slice(&memory[offset + VirtioNetHeader::SIZE..offset + len]);
                        skip_header = false;
                    } else if !skip_header {
                        packet_data.extend_from_slice(&memory[offset..offset + len]);
                    }
                }
            }

            // Follow the chain
            let mut next_idx = if first_desc.has_next() { Some(first_desc.next) } else { None };
            while let Some(idx) = next_idx {
                if let Some(desc) = self.tx_queue.read_descriptor(memory, idx) {
                    if !desc.is_write_only() {
                        let offset = desc.addr as usize;
                        let len = desc.len as usize;
                        if offset + len <= memory.len() {
                            packet_data.extend_from_slice(&memory[offset..offset + len]);
                        }
                    }
                    next_idx = if desc.has_next() { Some(desc.next) } else { None };
                } else {
                    break;
                }
            }

            // Send the packet
            if !packet_data.is_empty() {
                let _ = self.backend.send(&packet_data);
            }

            // Add to used ring
            self.tx_queue.add_used(memory, head_idx, 0);
            processed = true;
        }

        if processed {
            self.interrupt_status |= 1;
        }

        processed
    }

    /// Process RX queue - receive packets from backend to guest.
    pub fn process_rx(&mut self, memory: &mut [u8]) -> bool {
        let mut processed = false;

        // Don't process if queue isn't ready
        if !self.rx_queue.ready {
            return false;
        }

        // Get available packet
        let packet = match self.pop_rx() {
            Some(p) => p,
            None => return false,
        };

        // Try to get an available buffer from RX queue
        if let Some((head_idx, first_desc)) = self.rx_queue.pop_available(memory) {
            let mut total_written = 0u32;

            if first_desc.is_write_only() {
                let offset = first_desc.addr as usize;
                let available_len = first_desc.len as usize;

                if offset + available_len <= memory.len() {
                    // Write virtio-net header
                    let header = VirtioNetHeader::default();
                    let header_bytes: [u8; VirtioNetHeader::SIZE] = unsafe {
                        std::mem::transmute_copy(&header)
                    };

                    let header_len = std::cmp::min(VirtioNetHeader::SIZE, available_len);
                    memory[offset..offset + header_len].copy_from_slice(&header_bytes[..header_len]);

                    // Write packet data after header
                    if available_len > VirtioNetHeader::SIZE {
                        let data_space = available_len - VirtioNetHeader::SIZE;
                        let data_len = std::cmp::min(packet.len(), data_space);
                        memory[offset + VirtioNetHeader::SIZE..offset + VirtioNetHeader::SIZE + data_len]
                            .copy_from_slice(&packet[..data_len]);

                        total_written = (VirtioNetHeader::SIZE + data_len) as u32;
                        processed = true;
                    }
                }
            }

            // IMPORTANT: Always add to used ring after popping from avail ring
            self.rx_queue.add_used(memory, head_idx, total_written);
        } else {
            // No available buffer, re-queue the packet
            self.rx_pending.push_front(packet);
        }

        if processed {
            self.interrupt_status |= 1;
        }

        processed
    }

    /// Process all queues.
    pub fn process_queues(&mut self, memory: &mut [u8]) -> bool {
        let tx = self.process_tx_mut(memory);
        let rx = self.process_rx(memory);
        tx || rx
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
        // Config space layout:
        // 0-5:  MAC address (6 bytes)
        // 6-7:  Status (2 bytes, if VIRTIO_NET_F_STATUS)
        let config = [
            self.mac[0],
            self.mac[1],
            self.mac[2],
            self.mac[3],
            self.mac[4],
            self.mac[5],
            (self.link_status & 0xFF) as u8,
            ((self.link_status >> 8) & 0xFF) as u8,
        ];

        let offset = offset as usize;
        if offset < config.len() && !data.is_empty() {
            let end = std::cmp::min(offset + data.len(), config.len());
            let len = end - offset;
            data[..len].copy_from_slice(&config[offset..end]);
        }
    }

    fn write_config(&mut self, _offset: u64, _data: &[u8]) {
        // Config is read-only
    }

    fn activate(&mut self) -> Result<()> {
        self.activated = true;
        Ok(())
    }

    fn reset(&mut self) {
        self.acked_features = 0;
        self.activated = false;
        self.rx_pending.clear();
        self.rx_queue.reset();
        self.tx_queue.reset();
        self.interrupt_status = 0;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_virtio_net_creation() {
        let net = VirtioNet::new();
        assert_eq!(net.mac()[0], 0x52); // Locally administered
        assert_eq!(net.mac()[1], 0x54);
        assert_eq!(net.device_type(), 1); // NET
    }

    #[test]
    fn test_virtio_net_config() {
        let net = VirtioNet::with_mac([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
        let mut data = [0u8; 6];
        net.read_config(0, &mut data);
        assert_eq!(data, [0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
    }

    #[test]
    fn test_loopback_backend() {
        let mut net = VirtioNet::with_backend(Box::new(LoopbackBackend::new()));

        // Send a packet
        let packet = vec![0x45, 0x00, 0x00, 0x20]; // Fake IP header
        net.send_packet(&packet).unwrap();

        // Should be available for RX
        assert!(net.has_rx_data());

        // Receive the same packet
        let rx = net.pop_rx().unwrap();
        assert_eq!(rx, packet);
    }
}
