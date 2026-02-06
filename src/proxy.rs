//! Host-side outbound proxy for guest internet access.
//!
//! This module implements the host side of the outbound proxy that allows
//! the guest VM to make TCP connections to the internet via vsock.
//!
//! ## Protocol
//!
//! The guest's outbound-proxy connects to the host on vsock port 7601 and
//! sends packets using a simple binary protocol:
//!
//! ```text
//! Packet Header (13 bytes):
//!   - type: u8 (0x01=Connect, 0x02=Response, 0x03=Data, 0x04=Close)
//!   - conn_key: u64 LE (connection identifier)
//!   - payload_len: u32 LE
//!
//! Connect Payload:
//!   - msg_type: u8 (0x01)
//!   - addr_type: u8 (0x01=IPv4, 0x03=Domain)
//!   - addr_len: u16 LE
//!   - address: [u8; addr_len]
//!   - port: u16 LE
//!
//! Response Payload (4 bytes):
//!   - msg_type: u8 (0x02)
//!   - status: u8 (0x00=Success, 0x02=Refused, 0x03=HostUnreach, 0x04=NetUnreach)
//!   - bound_port: u16 LE
//! ```

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

/// Default vsock port for the outbound proxy.
pub const OUTBOUND_PROXY_PORT: u32 = 7601;

/// Packet types in the proxy protocol.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PacketType {
    Connect = 0x01,
    Response = 0x02,
    Data = 0x03,
    Close = 0x04,
}

impl TryFrom<u8> for PacketType {
    type Error = io::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(PacketType::Connect),
            0x02 => Ok(PacketType::Response),
            0x03 => Ok(PacketType::Data),
            0x04 => Ok(PacketType::Close),
            _ => Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid packet type")),
        }
    }
}

/// Response status codes.
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum ResponseStatus {
    Success = 0x00,
    GeneralFailure = 0x01,
    ConnectionRefused = 0x02,
    HostUnreachable = 0x03,
    NetworkUnreachable = 0x04,
}

/// Proxy packet header.
#[derive(Debug)]
pub struct PacketHeader {
    pub pkt_type: PacketType,
    pub conn_key: u64,
    pub payload_len: u32,
}

impl PacketHeader {
    pub const SIZE: usize = 13;

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::SIZE);
        buf.push(self.pkt_type as u8);
        buf.extend_from_slice(&self.conn_key.to_le_bytes());
        buf.extend_from_slice(&self.payload_len.to_le_bytes());
        buf
    }

    pub fn decode(data: &[u8]) -> io::Result<Self> {
        if data.len() < Self::SIZE {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Packet too short"));
        }
        let pkt_type = PacketType::try_from(data[0])?;
        let conn_key = u64::from_le_bytes([
            data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8],
        ]);
        let payload_len = u32::from_le_bytes([data[9], data[10], data[11], data[12]]);
        Ok(Self { pkt_type, conn_key, payload_len })
    }
}

/// Connect request from guest.
#[derive(Debug)]
pub struct ConnectRequest {
    pub addr_type: u8,
    pub address: Vec<u8>,
    pub port: u16,
}

impl ConnectRequest {
    pub fn decode(data: &[u8]) -> io::Result<Self> {
        if data.len() < 6 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Connect request too short"));
        }
        let _msg_type = data[0]; // Should be 0x01
        let addr_type = data[1];
        let addr_len = u16::from_le_bytes([data[2], data[3]]) as usize;

        if data.len() < 4 + addr_len + 2 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Connect request truncated"));
        }

        let address = data[4..4 + addr_len].to_vec();
        let port = u16::from_le_bytes([data[4 + addr_len], data[5 + addr_len]]);

        Ok(Self { addr_type, address, port })
    }

    /// Get the target address as a string for connection.
    pub fn target_string(&self) -> io::Result<String> {
        match self.addr_type {
            0x01 => {
                // IPv4
                if self.address.len() != 4 {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid IPv4 address"));
                }
                Ok(format!("{}.{}.{}.{}:{}",
                    self.address[0], self.address[1], self.address[2], self.address[3],
                    self.port))
            }
            0x03 => {
                // Domain name
                let domain = String::from_utf8(self.address.clone())
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid domain name"))?;
                Ok(format!("{}:{}", domain, self.port))
            }
            _ => Err(io::Error::new(io::ErrorKind::InvalidData, "Unsupported address type")),
        }
    }
}

/// Host-side outbound proxy handler.
///
/// This runs in a separate thread and handles connections from the guest's
/// outbound-proxy via vsock.
///
/// Note: This struct uses raw file descriptors and is only available on Unix platforms.
/// For cross-platform code, use `ProxyConnectionManager` instead.
#[cfg(unix)]
pub struct OutboundProxy {
    /// Active TCP connections (conn_key -> TcpStream)
    connections: Arc<Mutex<HashMap<u64, TcpStream>>>,
    /// Running flag
    running: Arc<std::sync::atomic::AtomicBool>,
}

#[cfg(unix)]
impl OutboundProxy {
    /// Create a new outbound proxy.
    pub fn new() -> Self {
        Self {
            connections: Arc::new(Mutex::new(HashMap::new())),
            running: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        }
    }

    /// Handle a vsock connection from the guest.
    ///
    /// This is called for each connection from the guest's outbound-proxy.
    /// It reads packets, makes TCP connections, and relays data.
    pub fn handle_connection(&self, vsock_fd: i32) -> io::Result<()> {
        eprintln!("[PROXY] New connection from guest");

        // Set socket to non-blocking for the relay loop
        unsafe {
            let flags = libc::fcntl(vsock_fd, libc::F_GETFL);
            libc::fcntl(vsock_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }

        let mut header_buf = [0u8; PacketHeader::SIZE];
        let mut tcp_stream: Option<TcpStream> = None;
        let mut conn_key: u64 = 0;

        loop {
            if !self.running.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }

            // Try to read packet header
            let n = unsafe {
                libc::read(
                    vsock_fd,
                    header_buf.as_mut_ptr() as *mut libc::c_void,
                    header_buf.len(),
                )
            };

            if n == 0 {
                // Connection closed
                eprintln!("[PROXY] Connection {} closed by guest", conn_key);
                break;
            } else if n < 0 {
                let errno = io::Error::last_os_error().raw_os_error().unwrap_or(0);
                if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
                    // No data available, check if we have data from TCP to send back
                    if let Some(ref mut stream) = tcp_stream {
                        let mut buf = [0u8; 8192];
                        match stream.read(&mut buf) {
                            Ok(0) => {
                                // TCP closed
                                eprintln!("[PROXY] TCP connection closed for {}", conn_key);
                                self.send_close(vsock_fd, conn_key);
                                break;
                            }
                            Ok(n) => {
                                // Send data back to guest
                                self.send_data(vsock_fd, conn_key, &buf[..n]);
                            }
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                                // No data from TCP either, sleep briefly
                                thread::sleep(Duration::from_millis(1));
                            }
                            Err(e) => {
                                eprintln!("[PROXY] TCP read error: {}", e);
                                self.send_close(vsock_fd, conn_key);
                                break;
                            }
                        }
                    } else {
                        thread::sleep(Duration::from_millis(1));
                    }
                    continue;
                }
                // Real error
                return Err(io::Error::last_os_error());
            }

            // Read remaining header bytes if needed
            let mut total_read = n as usize;
            while total_read < PacketHeader::SIZE {
                let n = unsafe {
                    libc::read(
                        vsock_fd,
                        header_buf[total_read..].as_mut_ptr() as *mut libc::c_void,
                        PacketHeader::SIZE - total_read,
                    )
                };
                if n <= 0 {
                    if n == 0 {
                        break;
                    }
                    let errno = io::Error::last_os_error().raw_os_error().unwrap_or(0);
                    if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
                        thread::sleep(Duration::from_micros(100));
                        continue;
                    }
                    return Err(io::Error::last_os_error());
                }
                total_read += n as usize;
            }

            if total_read < PacketHeader::SIZE {
                break;
            }

            let header = PacketHeader::decode(&header_buf)?;
            conn_key = header.conn_key;

            // Read payload if any
            let mut payload = vec![0u8; header.payload_len as usize];
            if header.payload_len > 0 {
                let mut payload_read = 0;
                while payload_read < payload.len() {
                    let n = unsafe {
                        libc::read(
                            vsock_fd,
                            payload[payload_read..].as_mut_ptr() as *mut libc::c_void,
                            payload.len() - payload_read,
                        )
                    };
                    if n <= 0 {
                        if n == 0 {
                            break;
                        }
                        let errno = io::Error::last_os_error().raw_os_error().unwrap_or(0);
                        if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
                            thread::sleep(Duration::from_micros(100));
                            continue;
                        }
                        return Err(io::Error::last_os_error());
                    }
                    payload_read += n as usize;
                }
            }

            // Handle packet
            match header.pkt_type {
                PacketType::Connect => {
                    let req = ConnectRequest::decode(&payload)?;
                    let target = req.target_string()?;
                    eprintln!("[PROXY] CONNECT {} -> {}", conn_key, target);

                    // Make TCP connection
                    match self.connect_tcp(&target) {
                        Ok(stream) => {
                            eprintln!("[PROXY] Connected to {}", target);
                            tcp_stream = Some(stream);
                            self.send_response(vsock_fd, conn_key, ResponseStatus::Success);
                        }
                        Err(e) => {
                            eprintln!("[PROXY] Connection failed: {}", e);
                            let status = match e.kind() {
                                io::ErrorKind::ConnectionRefused => ResponseStatus::ConnectionRefused,
                                io::ErrorKind::AddrNotAvailable => ResponseStatus::HostUnreachable,
                                _ => ResponseStatus::GeneralFailure,
                            };
                            self.send_response(vsock_fd, conn_key, status);
                            break;
                        }
                    }
                }
                PacketType::Data => {
                    // Forward data to TCP connection
                    if let Some(ref mut stream) = tcp_stream {
                        if let Err(e) = stream.write_all(&payload) {
                            eprintln!("[PROXY] TCP write error: {}", e);
                            self.send_close(vsock_fd, conn_key);
                            break;
                        }
                    }
                }
                PacketType::Close => {
                    eprintln!("[PROXY] Close request for {}", conn_key);
                    break;
                }
                PacketType::Response => {
                    // Host doesn't receive responses
                }
            }
        }

        // Cleanup
        if let Some(stream) = tcp_stream {
            drop(stream);
        }
        self.connections.lock().unwrap().remove(&conn_key);

        Ok(())
    }

    /// Connect to a TCP target.
    fn connect_tcp(&self, target: &str) -> io::Result<TcpStream> {
        let addrs: Vec<_> = target.to_socket_addrs()?.collect();
        if addrs.is_empty() {
            return Err(io::Error::new(io::ErrorKind::AddrNotAvailable, "No addresses found"));
        }

        let stream = TcpStream::connect_timeout(&addrs[0], Duration::from_secs(30))?;
        stream.set_nonblocking(true)?;
        stream.set_read_timeout(Some(Duration::from_secs(300)))?;
        stream.set_write_timeout(Some(Duration::from_secs(30)))?;

        Ok(stream)
    }

    /// Send a response packet to the guest.
    fn send_response(&self, vsock_fd: i32, conn_key: u64, status: ResponseStatus) {
        let header = PacketHeader {
            pkt_type: PacketType::Response,
            conn_key,
            payload_len: 4,
        };

        // Response payload: msg_type (0x02) + status + bound_port (0)
        let payload = [0x02, status as u8, 0x00, 0x00];

        let mut buf = header.encode();
        buf.extend_from_slice(&payload);

        unsafe {
            libc::write(vsock_fd, buf.as_ptr() as *const libc::c_void, buf.len());
        }
    }

    /// Send data packet to the guest.
    fn send_data(&self, vsock_fd: i32, conn_key: u64, data: &[u8]) {
        let header = PacketHeader {
            pkt_type: PacketType::Data,
            conn_key,
            payload_len: data.len() as u32,
        };

        let mut buf = header.encode();
        buf.extend_from_slice(data);

        unsafe {
            libc::write(vsock_fd, buf.as_ptr() as *const libc::c_void, buf.len());
        }
    }

    /// Send close packet to the guest.
    fn send_close(&self, vsock_fd: i32, conn_key: u64) {
        let header = PacketHeader {
            pkt_type: PacketType::Close,
            conn_key,
            payload_len: 0,
        };

        let buf = header.encode();

        unsafe {
            libc::write(vsock_fd, buf.as_ptr() as *const libc::c_void, buf.len());
        }
    }

    /// Stop the proxy.
    pub fn stop(&self) {
        self.running.store(false, std::sync::atomic::Ordering::Relaxed);
    }
}

#[cfg(unix)]
impl Default for OutboundProxy {
    fn default() -> Self {
        Self::new()
    }
}

/// Proxy connection manager for use with VirtIO vsock emulation.
///
/// This manager handles the proxy protocol for guest internet access,
/// working with data buffers rather than raw file descriptors.
pub struct ProxyConnectionManager {
    /// Active TCP connections (conn_key -> TcpStream)
    connections: HashMap<u64, TcpStream>,
    /// Pending responses to send to guest
    pending_responses: Vec<Vec<u8>>,
    /// Buffer for accumulating incoming data (handles partial packets)
    recv_buffer: Vec<u8>,
}

impl ProxyConnectionManager {
    /// Create a new proxy connection manager.
    pub fn new() -> Self {
        Self {
            connections: HashMap::new(),
            pending_responses: Vec::new(),
            recv_buffer: Vec::new(),
        }
    }

    /// Process incoming data from guest (via vsock RW packet).
    ///
    /// The data may contain multiple proxy protocol packets or partial packets.
    /// Returns any response packets that should be sent back to the guest.
    pub fn process_incoming(&mut self, data: &[u8]) -> Vec<Vec<u8>> {
        self.recv_buffer.extend_from_slice(data);
        self.pending_responses.clear();

        // Process complete packets from the buffer
        while self.recv_buffer.len() >= PacketHeader::SIZE {
            let header = match PacketHeader::decode(&self.recv_buffer) {
                Ok(h) => h,
                Err(_) => {
                    eprintln!("[PROXY] Invalid packet header");
                    self.recv_buffer.clear();
                    break;
                }
            };

            let total_len = PacketHeader::SIZE + header.payload_len as usize;
            if self.recv_buffer.len() < total_len {
                // Incomplete packet, wait for more data
                break;
            }

            // Extract complete packet
            let payload = self.recv_buffer[PacketHeader::SIZE..total_len].to_vec();
            self.recv_buffer.drain(..total_len);

            // Handle packet
            self.handle_packet(&header, &payload);
        }

        std::mem::take(&mut self.pending_responses)
    }

    /// Poll TCP connections for incoming data.
    ///
    /// Returns data packets to send back to guest.
    pub fn poll_tcp(&mut self) -> Vec<(u64, Vec<u8>)> {
        let mut data_packets = Vec::new();

        // Get list of connection keys to iterate
        let conn_keys: Vec<u64> = self.connections.keys().copied().collect();

        for conn_key in conn_keys {
            if let Some(stream) = self.connections.get_mut(&conn_key) {
                let mut buf = [0u8; 8192];
                match stream.read(&mut buf) {
                    Ok(0) => {
                        // Connection closed
                        eprintln!("[PROXY] TCP connection {} closed by server", conn_key);
                        self.connections.remove(&conn_key);
                        // Send CLOSE packet to guest
                        let close_pkt = Self::build_close_packet(conn_key);
                        data_packets.push((conn_key, close_pkt));
                    }
                    Ok(n) => {
                        // Build DATA packet for guest
                        let data_pkt = Self::build_data_packet(conn_key, &buf[..n]);
                        data_packets.push((conn_key, data_pkt));
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        // No data available, continue
                    }
                    Err(e) => {
                        eprintln!("[PROXY] TCP read error for {}: {}", conn_key, e);
                        self.connections.remove(&conn_key);
                        // Send CLOSE packet to guest
                        let close_pkt = Self::build_close_packet(conn_key);
                        data_packets.push((conn_key, close_pkt));
                    }
                }
            }
        }

        data_packets
    }

    /// Handle a complete proxy protocol packet.
    fn handle_packet(&mut self, header: &PacketHeader, payload: &[u8]) {
        match header.pkt_type {
            PacketType::Connect => {
                self.handle_connect(header.conn_key, payload);
            }
            PacketType::Data => {
                self.handle_data(header.conn_key, payload);
            }
            PacketType::Close => {
                self.handle_close(header.conn_key);
            }
            PacketType::Response => {
                // Host doesn't receive Response packets from guest
            }
        }
    }

    /// Handle CONNECT request from guest.
    fn handle_connect(&mut self, conn_key: u64, payload: &[u8]) {
        let req = match ConnectRequest::decode(payload) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("[PROXY] Invalid CONNECT request: {}", e);
                self.send_response(conn_key, ResponseStatus::GeneralFailure);
                return;
            }
        };

        let target = match req.target_string() {
            Ok(t) => t,
            Err(e) => {
                eprintln!("[PROXY] Invalid target address: {}", e);
                self.send_response(conn_key, ResponseStatus::GeneralFailure);
                return;
            }
        };

        eprintln!("[PROXY] CONNECT {} -> {}", conn_key, target);

        // Make TCP connection
        match Self::connect_tcp(&target) {
            Ok(stream) => {
                eprintln!("[PROXY] Connected to {}", target);
                self.connections.insert(conn_key, stream);
                self.send_response(conn_key, ResponseStatus::Success);
            }
            Err(e) => {
                eprintln!("[PROXY] Connection to {} failed: {}", target, e);
                let status = match e.kind() {
                    io::ErrorKind::ConnectionRefused => ResponseStatus::ConnectionRefused,
                    io::ErrorKind::AddrNotAvailable => ResponseStatus::HostUnreachable,
                    _ => ResponseStatus::GeneralFailure,
                };
                self.send_response(conn_key, status);
            }
        }
    }

    /// Handle DATA packet from guest.
    fn handle_data(&mut self, conn_key: u64, payload: &[u8]) {
        if let Some(stream) = self.connections.get_mut(&conn_key) {
            if let Err(e) = stream.write_all(payload) {
                eprintln!("[PROXY] TCP write error for {}: {}", conn_key, e);
                self.connections.remove(&conn_key);
                // Queue close packet
                let close_pkt = Self::build_close_packet(conn_key);
                self.pending_responses.push(close_pkt);
            }
        } else {
            eprintln!("[PROXY] DATA for unknown connection {}", conn_key);
        }
    }

    /// Handle CLOSE request from guest.
    fn handle_close(&mut self, conn_key: u64) {
        eprintln!("[PROXY] CLOSE {}", conn_key);
        self.connections.remove(&conn_key);
    }

    /// Send a response packet to the guest.
    fn send_response(&mut self, conn_key: u64, status: ResponseStatus) {
        let header = PacketHeader {
            pkt_type: PacketType::Response,
            conn_key,
            payload_len: 4,
        };

        // Response payload: msg_type (0x02) + status + bound_port (0)
        let payload = [0x02, status as u8, 0x00, 0x00];

        let mut pkt = header.encode();
        pkt.extend_from_slice(&payload);
        self.pending_responses.push(pkt);
    }

    /// Build a DATA packet to send to guest.
    fn build_data_packet(conn_key: u64, data: &[u8]) -> Vec<u8> {
        let header = PacketHeader {
            pkt_type: PacketType::Data,
            conn_key,
            payload_len: data.len() as u32,
        };

        let mut pkt = header.encode();
        pkt.extend_from_slice(data);
        pkt
    }

    /// Build a CLOSE packet to send to guest.
    fn build_close_packet(conn_key: u64) -> Vec<u8> {
        let header = PacketHeader {
            pkt_type: PacketType::Close,
            conn_key,
            payload_len: 0,
        };
        header.encode()
    }

    /// Connect to a TCP target.
    fn connect_tcp(target: &str) -> io::Result<TcpStream> {
        let addrs: Vec<_> = target.to_socket_addrs()?.collect();
        if addrs.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "No addresses found",
            ));
        }

        let stream = TcpStream::connect_timeout(&addrs[0], Duration::from_secs(30))?;
        stream.set_nonblocking(true)?;
        stream.set_read_timeout(Some(Duration::from_secs(300)))?;
        stream.set_write_timeout(Some(Duration::from_secs(30)))?;

        Ok(stream)
    }

    /// Check if there are any active connections.
    pub fn has_connections(&self) -> bool {
        !self.connections.is_empty()
    }

    /// Get the number of active connections.
    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }
}

impl Default for ProxyConnectionManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Create a vsock listener on the host side.
///
/// This listens for connections from the guest VM on the specified port.
#[cfg(target_os = "macos")]
pub fn create_vsock_listener(port: u32) -> io::Result<i32> {
    // On macOS with HVF, we need to use a different approach.
    // The guest connects to the host via the virtio-vsock device,
    // and we handle it through the VirtioVsock device emulation.
    //
    // This function is a placeholder - the actual vsock handling
    // is done in the VmRuntime by processing vsock packets.
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Host vsock listener not directly supported on macOS - use VmRuntime integration"
    ))
}

#[cfg(target_os = "windows")]
pub fn create_vsock_listener(_port: u32) -> io::Result<i32> {
    // Windows uses TCP over localhost for VM communication (WSL2 shares the host network namespace).
    // This is handled through the TcpVsockBridge in the WSL2 backend.
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Host vsock listener not directly supported on Windows - use VmRuntime integration"
    ))
}

#[cfg(target_os = "linux")]
pub fn create_vsock_listener(port: u32) -> io::Result<i32> {
    use std::os::unix::io::RawFd;

    // AF_VSOCK = 40, SOCK_STREAM = 1
    let fd: RawFd = unsafe { libc::socket(40, 1, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    // sockaddr_vm structure
    #[repr(C)]
    struct SockaddrVm {
        svm_family: u16,
        svm_reserved1: u16,
        svm_port: u32,
        svm_cid: u32,
        svm_zero: [u8; 4],
    }

    let addr = SockaddrVm {
        svm_family: 40, // AF_VSOCK
        svm_reserved1: 0,
        svm_port: port,
        svm_cid: 2, // VMADDR_CID_HOST
        svm_zero: [0; 4],
    };

    let ret = unsafe {
        libc::bind(
            fd,
            &addr as *const SockaddrVm as *const libc::sockaddr,
            std::mem::size_of::<SockaddrVm>() as u32,
        )
    };

    if ret < 0 {
        unsafe { libc::close(fd) };
        return Err(io::Error::last_os_error());
    }

    let ret = unsafe { libc::listen(fd, 10) };
    if ret < 0 {
        unsafe { libc::close(fd) };
        return Err(io::Error::last_os_error());
    }

    Ok(fd)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_header_encode_decode() {
        let header = PacketHeader {
            pkt_type: PacketType::Connect,
            conn_key: 12345,
            payload_len: 100,
        };

        let encoded = header.encode();
        assert_eq!(encoded.len(), PacketHeader::SIZE);

        let decoded = PacketHeader::decode(&encoded).unwrap();
        assert_eq!(decoded.pkt_type, PacketType::Connect);
        assert_eq!(decoded.conn_key, 12345);
        assert_eq!(decoded.payload_len, 100);
    }

    #[test]
    fn test_connect_request_ipv4() {
        // msg_type=1, addr_type=1 (IPv4), addr_len=4, addr=[8,8,8,8], port=53
        let data = [0x01, 0x01, 0x04, 0x00, 8, 8, 8, 8, 53, 0];
        let req = ConnectRequest::decode(&data).unwrap();
        assert_eq!(req.addr_type, 0x01);
        assert_eq!(req.address, vec![8, 8, 8, 8]);
        assert_eq!(req.port, 53);
        assert_eq!(req.target_string().unwrap(), "8.8.8.8:53");
    }

    #[test]
    fn test_connect_request_domain() {
        // msg_type=1, addr_type=3 (domain), addr_len=11, addr="example.com", port=80
        let domain = b"example.com";
        let mut data = vec![0x01, 0x03, domain.len() as u8, 0x00];
        data.extend_from_slice(domain);
        data.extend_from_slice(&80u16.to_le_bytes());

        let req = ConnectRequest::decode(&data).unwrap();
        assert_eq!(req.addr_type, 0x03);
        assert_eq!(req.address, domain.to_vec());
        assert_eq!(req.port, 80);
        assert_eq!(req.target_string().unwrap(), "example.com:80");
    }
}
