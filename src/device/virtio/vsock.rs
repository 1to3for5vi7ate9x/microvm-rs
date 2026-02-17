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
use crate::debug_vsock;
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

    /// Connect to a port on the host (guest-initiated).
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

    /// Connect to a port on the guest (host-initiated).
    /// This sends a REQUEST from host to guest - guest must have a listener on that port.
    pub fn connect_to_guest(&mut self, local_port: u32, guest_port: u32) -> Result<()> {
        let key = ConnKey {
            local_port,
            peer_cid: self.guest_cid,
            peer_port: guest_port,
        };

        debug_vsock!("[VSOCK] connect_to_guest: host_port={} -> guest_cid={} guest_port={}",
                  local_port, self.guest_cid, guest_port);

        // Create connection in Connecting state
        let conn = VsockConnection::new(local_port, self.guest_cid, guest_port);
        self.connections.insert(key, conn);

        // Queue REQUEST packet from host to guest
        let mut pkt = vec![0u8; VsockHeader::SIZE];
        self.write_response_header(
            &mut pkt,
            self.guest_cid,  // dst_cid = guest
            guest_port,      // dst_port = guest's listening port
            local_port,      // src_port = host's local port
            0,
            pkt_type::STREAM,
            op::REQUEST,
        );
        debug_vsock!("[VSOCK] Queued REQUEST packet: src_cid=2 dst_cid={} src_port={} dst_port={} op={}",
                  self.guest_cid, local_port, guest_port, op::REQUEST);
        self.rx_pending.push_back(pkt);

        Ok(())
    }

    /// Check if a host-to-guest connection is established.
    pub fn is_connected_to_guest(&self, local_port: u32, guest_port: u32) -> bool {
        let key = ConnKey {
            local_port,
            peer_cid: self.guest_cid,
            peer_port: guest_port,
        };
        self.connections.get(&key)
            .map(|c| c.state == ConnState::Connected)
            .unwrap_or(false)
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

        // Parse header fields
        // VsockHeader layout:
        //   src_cid: u64  (0-7)
        //   dst_cid: u64  (8-15)
        //   src_port: u32 (16-19)
        //   dst_port: u32 (20-23)
        //   len: u32      (24-27)
        //   type_: u16    (28-29)
        //   op: u16       (30-31)
        //   flags: u32    (32-35)
        //   buf_alloc: u32(36-39)
        //   fwd_cnt: u32  (40-43)
        let src_cid = u64::from_le_bytes([data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]]);
        let dst_cid = u64::from_le_bytes([data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15]]);
        let src_port = u32::from_le_bytes([data[16], data[17], data[18], data[19]]);
        let dst_port = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);
        let _len = u32::from_le_bytes([data[24], data[25], data[26], data[27]]);
        let _type = u16::from_le_bytes([data[28], data[29]]);
        let op = u16::from_le_bytes([data[30], data[31]]);

        // For incoming packets from guest:
        // - src_cid = guest's CID
        // - dst_cid = host's CID (should be 2)
        // - src_port = guest's port
        // - dst_port = host's port (what guest is connecting to)

        // Key for looking up connections (from HOST perspective)
        let key = ConnKey {
            local_port: dst_port,     // Our port
            peer_cid: src_cid,        // Guest's CID
            peer_port: src_port,      // Guest's port
        };

        debug_vsock!("[VSOCK] TX packet from guest: src_cid={} dst_cid={} src_port={} dst_port={} op={}",
                  src_cid, dst_cid, src_port, dst_port, op);

        match op {
            op::REQUEST => {
                // Incoming connection request from guest - accept if we have a listener
                debug_vsock!("[VSOCK] Guest REQUEST: src_port={} dst_port={} have_listener={}",
                          src_port, dst_port, self.listeners.contains_key(&dst_port));
                if self.listeners.contains_key(&dst_port) {
                    let mut conn = VsockConnection::new(dst_port, src_cid, src_port);
                    conn.state = ConnState::Connected;
                    self.connections.insert(key.clone(), conn);

                    // Queue RESPONSE packet to guest
                    // From host perspective: we send FROM host TO guest
                    let mut pkt = vec![0u8; VsockHeader::SIZE];
                    self.write_response_header(
                        &mut pkt,
                        src_cid,      // dst_cid = guest
                        src_port,     // dst_port = guest's port
                        dst_port,     // src_port = our port (1234)
                        0,
                        pkt_type::STREAM,
                        op::RESPONSE,
                    );
                    self.rx_pending.push_back(pkt);
                }
            }
            op::RESPONSE => {
                // Connection accepted
                debug_vsock!("[VSOCK] Guest RESPONSE: looking for connection local_port={} peer_cid={} peer_port={}",
                          key.local_port, key.peer_cid, key.peer_port);
                if let Some(conn) = self.connections.get_mut(&key) {
                    debug_vsock!("[VSOCK] Connection ACCEPTED! Transitioning to Connected");
                    conn.state = ConnState::Connected;
                } else {
                    debug_vsock!("[VSOCK] No matching connection found for RESPONSE!");
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
    /// Supports descriptor chains for large packets.
    pub fn process_rx(&mut self, memory: &mut [u8]) -> bool {
        static LOGGED_STUCK: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

        let mut delivered = false;
        let mut delivered_count = 0;

        // Don't process if queue isn't ready
        if !self.rx_queue.ready {
            return false;
        }

        while let Some(pkt) = self.rx_pending.front() {
            // Get an available buffer from the guest
            if let Some((head_idx, first_desc)) = self.rx_queue.pop_available(memory) {
                // Walk the descriptor chain to calculate total capacity
                let mut total_capacity: usize = 0;
                let mut chain: Vec<super::queue::Descriptor> = Vec::new();
                let mut current_desc = first_desc;

                loop {
                    if current_desc.is_write_only() {
                        total_capacity += current_desc.len as usize;
                        chain.push(current_desc);
                    }

                    if current_desc.has_next() {
                        if let Some(next_desc) = self.rx_queue.read_descriptor(memory, current_desc.next) {
                            current_desc = next_desc;
                        } else {
                            break;
                        }
                    } else {
                        break;
                    }
                }

                if total_capacity < pkt.len() {
                    // Chain doesn't have enough space, skip (will log in exhausted block)
                    self.rx_queue.add_used(memory, head_idx, 0);
                    continue;
                }

                // Write packet across the descriptor chain
                let mut pkt_offset = 0;
                let mut write_success = true;

                for desc in &chain {
                    if pkt_offset >= pkt.len() {
                        break;
                    }

                    let bytes_to_write = std::cmp::min(desc.len as usize, pkt.len() - pkt_offset);
                    let mem_offset = super::queue::gpa_to_offset(desc.addr);

                    if let Some(offset) = mem_offset {
                        if offset + bytes_to_write <= memory.len() {
                            memory[offset..offset + bytes_to_write]
                                .copy_from_slice(&pkt[pkt_offset..pkt_offset + bytes_to_write]);
                            pkt_offset += bytes_to_write;
                        } else {
                            write_success = false;
                            break;
                        }
                    } else {
                        write_success = false;
                        break;
                    }
                }

                if write_success && pkt_offset == pkt.len() {
                    self.rx_queue.add_used(memory, head_idx, pkt.len() as u32);
                    self.rx_pending.pop_front();
                    delivered = true;
                    delivered_count += 1;
                } else {
                    self.rx_queue.add_used(memory, head_idx, 0);
                }
            } else {
                // No more available buffers - log diagnostic info once
                if !LOGGED_STUCK.swap(true, std::sync::atomic::Ordering::SeqCst) {
                    // Read avail ring index from guest memory
                    let avail_idx = if self.rx_queue.avail_ring >= super::queue::RAM_BASE {
                        let offset = (self.rx_queue.avail_ring - super::queue::RAM_BASE) as usize + 2;
                        if offset + 2 <= memory.len() {
                            u16::from_le_bytes([memory[offset], memory[offset + 1]])
                        } else {
                            0
                        }
                    } else {
                        0
                    };
                    eprintln!("[VSOCK] RX BUFFERS EXHAUSTED - diagnostic info:");
                    eprintln!("[VSOCK]   rx_pending: {} packets", self.rx_pending.len());
                    eprintln!("[VSOCK]   rx_queue.ready: {}", self.rx_queue.ready);
                    eprintln!("[VSOCK]   rx_queue.size: {}", self.rx_queue.size);
                    eprintln!("[VSOCK]   rx_queue.last_avail_idx: {}", self.rx_queue.last_avail_idx);
                    eprintln!("[VSOCK]   guest avail_idx: {}", avail_idx);
                    eprintln!("[VSOCK]   rx_queue.avail_ring: 0x{:x}", self.rx_queue.avail_ring);
                    if let Some(pkt) = self.rx_pending.front() {
                        eprintln!("[VSOCK]   first pending packet size: {} bytes", pkt.len());
                    }
                }
                break;
            }
        }

        // Reset the stuck flag if we successfully delivered
        if delivered_count > 0 {
            LOGGED_STUCK.store(false, std::sync::atomic::Ordering::SeqCst);
        }

        if delivered {
            self.interrupt_status |= 1;
        }
        delivered
    }

    /// Check if TX queue is ready.
    pub fn tx_queue_ready(&self) -> bool {
        self.tx_queue.ready
    }

    /// Process TX queue - receive packets from guest.
    /// Returns any data that was received from the guest (for host to process).
    pub fn process_tx(&mut self, memory: &mut [u8]) -> Vec<Vec<u8>> {
        let mut received = Vec::new();

        // Don't process if queue isn't ready
        if !self.tx_queue.ready {
            return received;
        }

        while let Some((head_idx, first_desc)) = self.tx_queue.pop_available(memory) {
            if first_desc.is_write_only() {
                // TX descriptors should be readable
                self.tx_queue.add_used(memory, head_idx, 0);
                continue;
            }

            // Read packet from guest buffer, following descriptor chain
            let mut pkt = Vec::new();
            let mut current_desc = first_desc;
            loop {
                let offset = super::queue::gpa_to_offset(current_desc.addr);
                if let Some(offset) = offset {
                    let len = current_desc.len as usize;
                    if offset + len <= memory.len() {
                        pkt.extend_from_slice(&memory[offset..offset + len]);
                    }
                }

                // Follow chain if NEXT flag is set
                if current_desc.has_next() {
                    if let Some(next_desc) = self.tx_queue.read_descriptor(memory, current_desc.next) {
                        current_desc = next_desc;
                        continue;
                    }
                }
                break;
            }

            if !pkt.is_empty() {
                // Process the packet (connection handling, etc.)
                self.process_tx_packet(&pkt);
                received.push(pkt);
            }

            // IMPORTANT: Always add to used ring after popping from avail ring
            self.tx_queue.add_used(memory, head_idx, 0);
        }

        if !received.is_empty() {
            self.interrupt_status |= 1;
        }
        received
    }

    /// Helper to write a vsock header (from guest perspective - used when guest initiates).
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

    /// Helper to write a vsock header for HOST responses (src_cid = HOST).
    fn write_response_header(
        &self,
        buf: &mut [u8],
        dst_cid: u64,
        dst_port: u32,
        src_port: u32,
        len: u32,
        type_: u16,
        op: u16,
    ) {
        let src_cid = cid::HOST;  // Host is sending

        buf[0..8].copy_from_slice(&src_cid.to_le_bytes());
        buf[8..16].copy_from_slice(&dst_cid.to_le_bytes());
        buf[16..20].copy_from_slice(&src_port.to_le_bytes());
        buf[20..24].copy_from_slice(&dst_port.to_le_bytes());
        buf[24..28].copy_from_slice(&len.to_le_bytes());
        buf[28..30].copy_from_slice(&type_.to_le_bytes());
        buf[30..32].copy_from_slice(&op.to_le_bytes());
        // flags at 32-35 = 0
        // buf_alloc at 36-39 = 64KB buffer space for receiving
        let buf_alloc: u32 = 64 * 1024;
        buf[36..40].copy_from_slice(&buf_alloc.to_le_bytes());
        // fwd_cnt at 40-43 = 0 initially
    }

    /// Queue a raw packet to send to the guest (from host).
    /// Used for connection requests and other control packets.
    pub fn queue_raw_packet(&mut self, pkt: Vec<u8>) {
        self.rx_pending.push_back(pkt);
    }

    /// Queue a data packet to send to the guest (from host).
    /// Large payloads are chunked to fit in guest virtqueue buffers.
    /// Each chunk is a separate vsock RW packet that the guest reassembles at the socket layer.
    pub fn queue_data_packet(&mut self, dst_cid: u64, dst_port: u32, src_port: u32, data: &[u8]) {
        // Guest vsock buffers are 3776 bytes (VIRTIO_VSOCK_DEFAULT_RX_BUF_SIZE + headroom).
        // With 44-byte vsock header, max payload per packet is 3732 bytes.
        // Use 3700 to leave room for any alignment overhead.
        const MAX_PAYLOAD_PER_CHUNK: usize = 3700;

        if data.is_empty() {
            return;
        }

        let _num_chunks = (data.len() + MAX_PAYLOAD_PER_CHUNK - 1) / MAX_PAYLOAD_PER_CHUNK;

        let mut offset = 0;
        while offset < data.len() {
            let chunk_len = std::cmp::min(MAX_PAYLOAD_PER_CHUNK, data.len() - offset);
            let chunk = &data[offset..offset + chunk_len];

            let mut pkt = vec![0u8; VsockHeader::SIZE + chunk_len];
            self.write_response_header(
                &mut pkt,
                dst_cid,
                dst_port,
                src_port,
                chunk_len as u32,
                pkt_type::STREAM,
                op::RW,
            );
            pkt[VsockHeader::SIZE..].copy_from_slice(chunk);
            self.rx_pending.push_back(pkt);

            offset += chunk_len;
        }
    }

    /// Process echo - for any connection with pending rx data, echo it back.
    /// Returns true if any data was echoed.
    pub fn process_echo(&mut self) -> bool {
        let mut echoed = false;

        // Collect connection info for connections with data
        let connections_with_data: Vec<(ConnKey, Vec<u8>)> = self.connections
            .iter_mut()
            .filter(|(_, conn)| conn.state == ConnState::Connected && !conn.rx_buf.is_empty())
            .map(|(key, conn)| {
                let data: Vec<u8> = conn.rx_buf.drain(..).collect();
                (*key, data)
            })
            .collect();

        // Echo the data back
        for (key, data) in connections_with_data {
            if !data.is_empty() {
                // Echo back: src becomes dst
                self.queue_data_packet(key.peer_cid, key.peer_port, key.local_port, &data);
                echoed = true;
            }
        }

        echoed
    }

    /// Get list of active connections (for debugging).
    pub fn connections(&self) -> impl Iterator<Item = (&ConnKey, &VsockConnection)> {
        self.connections.iter()
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
