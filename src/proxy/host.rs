//! Host-side outbound proxy implementation.
//!
//! This module handles vsock connections from the guest and proxies
//! them to real TCP connections on the internet.

use super::protocol::{ConnectRequest, ConnectResponse, ProxyStatus, TargetAddress};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Default proxy port on vsock.
pub const DEFAULT_PROXY_PORT: u32 = 7601;

/// Connection ID counter.
static NEXT_CONN_ID: AtomicU64 = AtomicU64::new(1);

/// A single proxied connection.
#[derive(Debug)]
pub struct ProxiedConnection {
    /// Unique connection ID.
    pub id: u64,
    /// Target address.
    pub target: String,
    /// Target port.
    pub port: u16,
    /// TCP stream to the target.
    pub stream: TcpStream,
    /// Bytes sent to target.
    pub bytes_sent: u64,
    /// Bytes received from target.
    pub bytes_received: u64,
}

impl ProxiedConnection {
    /// Create a new connection to the target.
    pub fn connect(request: &ConnectRequest, timeout: Duration) -> io::Result<Self> {
        let id = NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed);
        let target = request.address.to_string();
        let port = request.port;

        // Resolve the address
        let addr = match &request.address {
            TargetAddress::IPv4(ip) => {
                format!("{}:{}", ip, port)
            }
            TargetAddress::IPv6(ip) => {
                format!("[{}]:{}", ip, port)
            }
            TargetAddress::Domain(name) => {
                format!("{}:{}", name, port)
            }
        };

        // Resolve and connect
        let socket_addr = addr
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Could not resolve address"))?;

        let stream = TcpStream::connect_timeout(&socket_addr, timeout)?;
        stream.set_nonblocking(true)?;

        Ok(Self {
            id,
            target,
            port,
            stream,
            bytes_sent: 0,
            bytes_received: 0,
        })
    }

    /// Get the local port of the connection.
    pub fn local_port(&self) -> u16 {
        self.stream.local_addr().map(|a| a.port()).unwrap_or(0)
    }

    /// Read data from the target (non-blocking).
    pub fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.stream.read(buf) {
            Ok(n) => {
                self.bytes_received += n as u64;
                Ok(n)
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(0),
            Err(e) => Err(e),
        }
    }

    /// Write data to the target.
    pub fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let n = self.stream.write(data)?;
        self.bytes_sent += n as u64;
        Ok(n)
    }

    /// Flush the connection.
    pub fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

/// Host-side vsock outbound proxy.
///
/// This handles incoming connection requests from the guest and creates
/// real TCP connections on the guest's behalf.
pub struct VsockOutboundProxy {
    /// Active connections indexed by guest's connection key (src_port << 32 | dst_port).
    connections: HashMap<u64, ProxiedConnection>,
    /// Connection timeout.
    timeout: Duration,
    /// Statistics: total connections.
    total_connections: u64,
    /// Statistics: failed connections.
    failed_connections: u64,
    /// Whether the proxy is running.
    running: Arc<AtomicBool>,
}

impl Default for VsockOutboundProxy {
    fn default() -> Self {
        Self::new()
    }
}

impl VsockOutboundProxy {
    /// Create a new outbound proxy.
    pub fn new() -> Self {
        Self {
            connections: HashMap::new(),
            timeout: Duration::from_secs(30),
            total_connections: 0,
            failed_connections: 0,
            running: Arc::new(AtomicBool::new(true)),
        }
    }

    /// Set the connection timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Handle a CONNECT request from the guest.
    ///
    /// Returns the response to send back and optionally a connection ID.
    pub fn handle_connect(&mut self, request: &ConnectRequest, conn_key: u64) -> (ConnectResponse, Option<u64>) {
        self.total_connections += 1;

        match ProxiedConnection::connect(request, self.timeout) {
            Ok(conn) => {
                let local_port = conn.local_port();
                let conn_id = conn.id;
                println!(
                    "[PROXY] Connection {} established: {} -> {}:{}",
                    conn_id, local_port, request.address, request.port
                );
                self.connections.insert(conn_key, conn);
                (ConnectResponse::success(local_port), Some(conn_id))
            }
            Err(e) => {
                self.failed_connections += 1;
                let status = ProxyStatus::from_io_error(&e);
                eprintln!(
                    "[PROXY] Connection failed to {}:{} - {}",
                    request.address, request.port, e
                );
                (ConnectResponse::failure(status), None)
            }
        }
    }

    /// Forward data from guest to the target.
    pub fn forward_to_target(&mut self, conn_key: u64, data: &[u8]) -> io::Result<usize> {
        if let Some(conn) = self.connections.get_mut(&conn_key) {
            let n = conn.write(data)?;
            conn.flush()?;
            Ok(n)
        } else {
            Err(io::Error::new(io::ErrorKind::NotFound, "Connection not found"))
        }
    }

    /// Read data from target to send to guest.
    pub fn read_from_target(&mut self, conn_key: u64, buf: &mut [u8]) -> io::Result<usize> {
        if let Some(conn) = self.connections.get_mut(&conn_key) {
            conn.read(buf)
        } else {
            Err(io::Error::new(io::ErrorKind::NotFound, "Connection not found"))
        }
    }

    /// Close a connection.
    pub fn close_connection(&mut self, conn_key: u64) {
        if let Some(conn) = self.connections.remove(&conn_key) {
            println!(
                "[PROXY] Connection {} closed: sent {} bytes, received {} bytes",
                conn.id, conn.bytes_sent, conn.bytes_received
            );
        }
    }

    /// Check if a connection exists.
    pub fn has_connection(&self, conn_key: u64) -> bool {
        self.connections.contains_key(&conn_key)
    }

    /// Get connection count.
    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }

    /// Get statistics.
    pub fn stats(&self) -> (u64, u64, usize) {
        (self.total_connections, self.failed_connections, self.connections.len())
    }

    /// Poll all connections for incoming data.
    /// Returns a vec of (conn_key, data) for connections with data available.
    pub fn poll_connections(&mut self) -> Vec<(u64, Vec<u8>)> {
        let mut results = Vec::new();
        let mut closed = Vec::new();

        for (&conn_key, conn) in &mut self.connections {
            let mut buf = vec![0u8; 8192];
            match conn.read(&mut buf) {
                Ok(0) => {
                    // Would block, no data available
                }
                Ok(n) => {
                    buf.truncate(n);
                    results.push((conn_key, buf));
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    // No data available
                }
                Err(e) if e.kind() == io::ErrorKind::ConnectionReset => {
                    closed.push(conn_key);
                }
                Err(e) if e.kind() == io::ErrorKind::BrokenPipe => {
                    closed.push(conn_key);
                }
                Err(_) => {
                    closed.push(conn_key);
                }
            }
        }

        // Remove closed connections
        for conn_key in closed {
            self.close_connection(conn_key);
        }

        results
    }

    /// Stop the proxy.
    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }

    /// Check if the proxy is running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }
}

/// Packet types for vsock proxy communication.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyPacketType {
    /// Connection request (uses ConnectRequest format).
    Connect = 0x01,
    /// Connection response (uses ConnectResponse format).
    Response = 0x02,
    /// Data packet.
    Data = 0x03,
    /// Close connection.
    Close = 0x04,
}

/// A proxy packet header for vsock communication.
#[derive(Debug, Clone)]
pub struct ProxyPacket {
    /// Packet type.
    pub pkt_type: ProxyPacketType,
    /// Connection key (src_port << 32 | dst_port on guest side).
    pub conn_key: u64,
    /// Payload length.
    pub payload_len: u32,
}

impl ProxyPacket {
    pub const HEADER_SIZE: usize = 13; // 1 + 8 + 4

    pub fn new(pkt_type: ProxyPacketType, conn_key: u64, payload_len: u32) -> Self {
        Self {
            pkt_type,
            conn_key,
            payload_len,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::HEADER_SIZE);
        buf.push(self.pkt_type as u8);
        buf.extend_from_slice(&self.conn_key.to_le_bytes());
        buf.extend_from_slice(&self.payload_len.to_le_bytes());
        buf
    }

    pub fn decode(data: &[u8]) -> io::Result<Self> {
        if data.len() < Self::HEADER_SIZE {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Packet too short"));
        }

        let pkt_type = match data[0] {
            0x01 => ProxyPacketType::Connect,
            0x02 => ProxyPacketType::Response,
            0x03 => ProxyPacketType::Data,
            0x04 => ProxyPacketType::Close,
            _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid packet type")),
        };

        let conn_key = u64::from_le_bytes([
            data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8],
        ]);
        let payload_len = u32::from_le_bytes([data[9], data[10], data[11], data[12]]);

        Ok(Self {
            pkt_type,
            conn_key,
            payload_len,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_proxy_packet_encode_decode() {
        let pkt = ProxyPacket::new(ProxyPacketType::Data, 0x12345678_9ABCDEF0, 1024);
        let encoded = pkt.encode();
        let decoded = ProxyPacket::decode(&encoded).unwrap();

        assert_eq!(decoded.pkt_type, ProxyPacketType::Data);
        assert_eq!(decoded.conn_key, 0x12345678_9ABCDEF0);
        assert_eq!(decoded.payload_len, 1024);
    }

    #[test]
    fn test_proxy_connect() {
        let mut proxy = VsockOutboundProxy::new().with_timeout(Duration::from_secs(5));

        // Try to connect to a local address (should fail unless something is listening)
        let request = ConnectRequest::ipv4(Ipv4Addr::new(127, 0, 0, 1), 12345);
        let (response, _) = proxy.handle_connect(&request, 1);

        // Connection should fail since nothing is listening on that port
        assert!(!response.is_success());
    }
}
