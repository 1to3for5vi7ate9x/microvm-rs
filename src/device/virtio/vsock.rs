//! Virtio vsock device.
//!
//! vsock provides a communication channel between the host and guest
//! without requiring network configuration. This is ideal for control
//! channels and is what Velocitty will use for VPN daemon communication.
//!
//! ## Virtqueues
//!
//! | Queue | Direction | Purpose |
//! |-------|-----------|---------|
//! | 0     | RX        | Receive data from host to guest |
//! | 1     | TX        | Transmit data from guest to host |
//! | 2     | Event     | Asynchronous events |
//!
//! ## CID Assignments
//!
//! | CID | Assignment |
//! |-----|------------|
//! | 0   | Hypervisor (reserved) |
//! | 1   | Reserved |
//! | 2   | Host |
//! | 3+  | Guest VMs |

use crate::device::VirtioDevice;
use crate::error::Result;
use std::collections::{HashMap, VecDeque};

use super::queue::Queue;

const QUEUE_SIZE: u16 = 128;

/// Well-known CID values.
pub mod cid {
    pub const HYPERVISOR: u64 = 0;
    pub const RESERVED: u64 = 1;
    pub const HOST: u64 = 2;
    pub const GUEST_MIN: u64 = 3;
}

/// Vsock packet header.
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct VsockHeader {
    pub src_cid: u64,
    pub dst_cid: u64,
    pub src_port: u32,
    pub dst_port: u32,
    pub len: u32,
    pub type_: u16,
    pub op: u16,
    pub flags: u32,
    pub buf_alloc: u32,
    pub fwd_cnt: u32,
}

impl VsockHeader {
    pub const SIZE: usize = 44;
}

/// Vsock packet types.
#[allow(dead_code)]
pub mod pkt_type {
    pub const STREAM: u16 = 1;
    pub const SEQPACKET: u16 = 2;
}

/// Vsock operations.
#[allow(dead_code)]
pub mod op {
    pub const INVALID: u16 = 0;
    pub const REQUEST: u16 = 1;      // Connection request
    pub const RESPONSE: u16 = 2;     // Connection response
    pub const RST: u16 = 3;          // Connection reset
    pub const SHUTDOWN: u16 = 4;     // Shutdown connection
    pub const RW: u16 = 5;           // Read/Write data
    pub const CREDIT_UPDATE: u16 = 6; // Credit update
    pub const CREDIT_REQUEST: u16 = 7; // Credit request
}

/// Connection state.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ConnState {
    /// Connection requested, waiting for response.
    Connecting,
    /// Connection established.
    Connected,
    /// Shutdown in progress.
    Closing,
    /// Connection closed.
    Closed,
}

/// A vsock connection identified by (local_port, peer_cid, peer_port).
#[derive(Clone, Debug)]
pub struct VsockConnection {
    pub local_port: u32,
    pub peer_cid: u64,
    pub peer_port: u32,
    pub state: ConnState,
    /// Buffer for incoming data
    pub rx_buf: VecDeque<u8>,
    /// Buffer for outgoing data
    pub tx_buf: VecDeque<u8>,
    /// Credits (flow control)
    pub buf_alloc: u32,
    pub fwd_cnt: u32,
}

impl VsockConnection {
    pub fn new(local_port: u32, peer_cid: u64, peer_port: u32) -> Self {
        Self {
            local_port,
            peer_cid,
            peer_port,
            state: ConnState::Connecting,
            rx_buf: VecDeque::new(),
            tx_buf: VecDeque::new(),
            buf_alloc: 64 * 1024, // 64KB default buffer
            fwd_cnt: 0,
        }
    }
}

/// Connection key for HashMap lookup.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ConnKey {
    pub local_port: u32,
    pub peer_cid: u64,
    pub peer_port: u32,
}

/// Virtio vsock device.
pub struct VirtioVsock {
    /// Guest CID (Context ID)
    guest_cid: u64,
    /// Device features
    features: u64,
    /// Acknowledged features
    acked_features: u64,
    /// Active connections
    connections: HashMap<ConnKey, VsockConnection>,
    /// Pending incoming connection requests (port -> callback)
    listeners: HashMap<u32, bool>,
    /// Pending packets to send to guest (host->guest)
    rx_pending: VecDeque<Vec<u8>>,
    /// Is the device activated?
    activated: bool,
    /// RX virtqueue (host->guest)
    rx_queue: Queue,
    /// TX virtqueue (guest->host)
    tx_queue: Queue,
    /// Event virtqueue
    event_queue: Queue,
    /// Interrupt status
    interrupt_status: u32,
}

impl VirtioVsock {
    /// Host CID.
    pub const HOST_CID: u64 = cid::HOST;

    /// Create a new virtio-vsock device with the specified guest CID.
    ///
    /// The CID must be >= 3 (0 is reserved, 1 is reserved, 2 is host).
    pub fn new(guest_cid: u64) -> Self {
        assert!(guest_cid >= cid::GUEST_MIN, "Guest CID must be >= 3");

        Self {
            guest_cid,
            features: super::feature::VIRTIO_F_VERSION_1,
            acked_features: 0,
            connections: HashMap::new(),
            listeners: HashMap::new(),
            rx_pending: VecDeque::new(),
            activated: false,
            rx_queue: Queue::new(QUEUE_SIZE),
            tx_queue: Queue::new(QUEUE_SIZE),
            event_queue: Queue::new(QUEUE_SIZE),
            interrupt_status: 0,
        }
    }

    /// Get the guest CID.
    pub fn guest_cid(&self) -> u64 {
        self.guest_cid
    }

    /// Listen for incoming connections on a port.
    pub fn listen(&mut self, port: u32) {
        self.listeners.insert(port, true);
    }

    /// Stop listening on a port.
    pub fn unlisten(&mut self, port: u32) {
        self.listeners.remove(&port);
    }

    /// Connect to a port on the host.
    pub fn connect(&mut self, local_port: u32, peer_port: u32) -> Result<()> {
        let key = ConnKey {
            local_port,
            peer_cid: Self::HOST_CID,
            peer_port,
        };

        // Create connection
        let conn = VsockConnection::new(local_port, Self::HOST_CID, peer_port);
        self.connections.insert(key, conn);

        // Queue connection request packet
        let mut pkt = vec![0u8; VsockHeader::SIZE];
        self.write_header(
            &mut pkt,
            Self::HOST_CID,
            peer_port,
            local_port,
            0,
            pkt_type::STREAM,
            op::REQUEST,
        );
        self.rx_pending.push_back(pkt);

        Ok(())
    }

    /// Send data on a connection.
    pub fn send(&mut self, local_port: u32, peer_cid: u64, peer_port: u32, data: &[u8]) -> Result<usize> {
        let key = ConnKey {
            local_port,
            peer_cid,
            peer_port,
        };

        if let Some(conn) = self.connections.get_mut(&key) {
            if conn.state != ConnState::Connected {
                return Err(crate::error::Error::InvalidState {
                    expected: "Connected".into(),
                    actual: format!("{:?}", conn.state),
                });
            }
            conn.tx_buf.extend(data);
            Ok(data.len())
        } else {
            Err(crate::error::Error::DeviceError("Connection not found".into()))
        }
    }

    /// Receive data from a connection.
    pub fn recv(&mut self, local_port: u32, peer_cid: u64, peer_port: u32, buf: &mut [u8]) -> Result<usize> {
        let key = ConnKey {
            local_port,
            peer_cid,
            peer_port,
        };

        if let Some(conn) = self.connections.get_mut(&key) {
            let len = std::cmp::min(buf.len(), conn.rx_buf.len());
            for (i, byte) in conn.rx_buf.drain(..len).enumerate() {
                buf[i] = byte;
            }
            Ok(len)
        } else {
            Err(crate::error::Error::DeviceError("Connection not found".into()))
        }
    }

    /// Close a connection.
    pub fn close(&mut self, local_port: u32, peer_cid: u64, peer_port: u32) {
        let key = ConnKey {
            local_port,
            peer_cid,
            peer_port,
        };

        if let Some(conn) = self.connections.get_mut(&key) {
            conn.state = ConnState::Closing;

            // Queue shutdown packet
            let mut pkt = vec![0u8; VsockHeader::SIZE];
            self.write_header(
                &mut pkt,
                peer_cid,
                peer_port,
                local_port,
                0,
                pkt_type::STREAM,
                op::SHUTDOWN,
            );
            self.rx_pending.push_back(pkt);
        }
    }

    /// Process a packet from the guest.
    pub fn process_tx_packet(&mut self, data: &[u8]) {
        if data.len() < VsockHeader::SIZE {
            return;
        }

        // Parse header (simplified - just read the op)
        let op = u16::from_le_bytes([data[40], data[41]]);
        let src_port = u32::from_le_bytes([data[16], data[17], data[18], data[19]]);
        let dst_cid = u64::from_le_bytes([data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15]]);
        let dst_port = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);

        let key = ConnKey {
            local_port: src_port,
            peer_cid: dst_cid,
            peer_port: dst_port,
        };

        match op {
            op::REQUEST => {
                // Incoming connection request - accept if we have a listener
                if self.listeners.contains_key(&dst_port) {
                    let mut conn = VsockConnection::new(dst_port, cid::HOST, src_port);
                    conn.state = ConnState::Connected;

                    let accept_key = ConnKey {
                        local_port: dst_port,
                        peer_cid: cid::HOST,
                        peer_port: src_port,
                    };
                    self.connections.insert(accept_key, conn);

                    // Queue response
                    let mut pkt = vec![0u8; VsockHeader::SIZE];
                    self.write_header(
                        &mut pkt,
                        cid::HOST,
                        src_port,
                        dst_port,
                        0,
                        pkt_type::STREAM,
                        op::RESPONSE,
                    );
                    self.rx_pending.push_back(pkt);
                }
            }
            op::RESPONSE => {
                // Connection accepted
                if let Some(conn) = self.connections.get_mut(&key) {
                    conn.state = ConnState::Connected;
                }
            }
            op::RST | op::SHUTDOWN => {
                // Connection closed
                if let Some(conn) = self.connections.get_mut(&key) {
                    conn.state = ConnState::Closed;
                }
            }
            op::RW => {
                // Data transfer
                if let Some(conn) = self.connections.get_mut(&key) {
                    let payload = &data[VsockHeader::SIZE..];
                    conn.rx_buf.extend(payload);
                }
            }
            _ => {}
        }
    }

    /// Get the next packet to send to the guest.
    pub fn get_rx_packet(&mut self) -> Option<Vec<u8>> {
        self.rx_pending.pop_front()
    }

    /// Check if there are packets waiting for the guest.
    pub fn has_rx_data(&self) -> bool {
        !self.rx_pending.is_empty()
    }

    /// Sync RX queue configuration from transport.
    pub fn sync_rx_queue(&mut self, queue: &Queue) {
        self.rx_queue.desc_table = queue.desc_table;
        self.rx_queue.avail_ring = queue.avail_ring;
        self.rx_queue.used_ring = queue.used_ring;
        self.rx_queue.size = queue.size;
        self.rx_queue.ready = queue.ready;
    }

    /// Sync TX queue configuration from transport.
    pub fn sync_tx_queue(&mut self, queue: &Queue) {
        self.tx_queue.desc_table = queue.desc_table;
        self.tx_queue.avail_ring = queue.avail_ring;
        self.tx_queue.used_ring = queue.used_ring;
        self.tx_queue.size = queue.size;
        self.tx_queue.ready = queue.ready;
    }

    /// Sync event queue configuration from transport.
    pub fn sync_event_queue(&mut self, queue: &Queue) {
        self.event_queue.desc_table = queue.desc_table;
        self.event_queue.avail_ring = queue.avail_ring;
        self.event_queue.used_ring = queue.used_ring;
        self.event_queue.size = queue.size;
        self.event_queue.ready = queue.ready;
    }

    /// Get interrupt status.
    pub fn interrupt_status(&self) -> u32 {
        self.interrupt_status
    }

    /// Acknowledge interrupt.
    pub fn ack_interrupt(&mut self, value: u32) {
        self.interrupt_status &= !value;
    }

    /// Process RX queue - send pending packets to guest.
    /// Returns true if any packets were delivered.
    pub fn process_rx(&mut self, memory: &mut [u8]) -> bool {
        let mut delivered = false;

        while let Some(pkt) = self.rx_pending.front() {
            // Get an available buffer from the guest
            if let Some((head_idx, desc)) = self.rx_queue.pop_available(memory) {
                if !desc.is_write_only() || (desc.len as usize) < pkt.len() {
                    // Buffer not suitable, skip
                    self.rx_queue.add_used(memory, head_idx, 0);
                    continue;
                }

                // Write packet to guest buffer
                let offset = super::queue::gpa_to_offset(desc.addr);
                if let Some(offset) = offset {
                    if offset + pkt.len() <= memory.len() {
                        memory[offset..offset + pkt.len()].copy_from_slice(pkt);
                        self.rx_queue.add_used(memory, head_idx, pkt.len() as u32);
                        self.rx_pending.pop_front();
                        delivered = true;
                    }
                }
            } else {
                // No more available buffers
                break;
            }
        }

        if delivered {
            self.interrupt_status |= 1;
        }
        delivered
    }

    /// Process TX queue - receive packets from guest.
    /// Returns any data that was received from the guest (for host to process).
    pub fn process_tx(&mut self, memory: &mut [u8]) -> Vec<Vec<u8>> {
        let mut received = Vec::new();

        while let Some((head_idx, first_desc)) = self.tx_queue.pop_available(memory) {
            if first_desc.is_write_only() {
                // TX descriptors should be readable
                self.tx_queue.add_used(memory, head_idx, 0);
                continue;
            }

            // Read packet from guest buffer
            let offset = super::queue::gpa_to_offset(first_desc.addr);
            if let Some(offset) = offset {
                let len = first_desc.len as usize;
                if offset + len <= memory.len() {
                    let mut pkt = vec![0u8; len];
                    pkt.copy_from_slice(&memory[offset..offset + len]);

                    // Process the packet (connection handling, etc.)
                    self.process_tx_packet(&pkt);
                    received.push(pkt);

                    self.tx_queue.add_used(memory, head_idx, 0);
                }
            }
        }

        if !received.is_empty() {
            self.interrupt_status |= 1;
        }
        received
    }

    /// Helper to write a vsock header.
    fn write_header(
        &self,
        buf: &mut [u8],
        dst_cid: u64,
        dst_port: u32,
        src_port: u32,
        len: u32,
        type_: u16,
        op: u16,
    ) {
        let src_cid = self.guest_cid;

        buf[0..8].copy_from_slice(&src_cid.to_le_bytes());
        buf[8..16].copy_from_slice(&dst_cid.to_le_bytes());
        buf[16..20].copy_from_slice(&src_port.to_le_bytes());
        buf[20..24].copy_from_slice(&dst_port.to_le_bytes());
        buf[24..28].copy_from_slice(&len.to_le_bytes());
        buf[28..30].copy_from_slice(&type_.to_le_bytes());
        buf[30..32].copy_from_slice(&op.to_le_bytes());
        // flags, buf_alloc, fwd_cnt initialized to 0
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
        self.activated = true;
        Ok(())
    }

    fn reset(&mut self) {
        self.acked_features = 0;
        self.activated = false;
        self.connections.clear();
        self.rx_pending.clear();
        self.rx_queue.reset();
        self.tx_queue.reset();
        self.event_queue.reset();
        self.interrupt_status = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vsock_creation() {
        let vsock = VirtioVsock::new(3);
        assert_eq!(vsock.guest_cid(), 3);
        assert_eq!(vsock.device_type(), 19); // VSOCK
    }

    #[test]
    fn test_vsock_config() {
        let vsock = VirtioVsock::new(42);
        let mut data = [0u8; 8];
        vsock.read_config(0, &mut data);
        assert_eq!(u64::from_le_bytes(data), 42);
    }

    #[test]
    fn test_vsock_listen() {
        let mut vsock = VirtioVsock::new(3);
        vsock.listen(1234);
        assert!(vsock.listeners.contains_key(&1234));
        vsock.unlisten(1234);
        assert!(!vsock.listeners.contains_key(&1234));
    }

    #[test]
    #[should_panic(expected = "Guest CID must be >= 3")]
    fn test_vsock_invalid_cid() {
        let _ = VirtioVsock::new(2); // Should panic - 2 is host CID
    }
}
